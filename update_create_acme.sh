#!/bin/bash
set -e

# === КОНФИГУРАЦИЯ ===
WEBFOLDER='/var/www/certload.iiko.ru/www/enhyujd56'
PDNS_URL="http://192.168.48.33:8081"
PDNS_CREDS='/etc/letsencrypt/pdns-api.ini'
API_KEY=$(grep dns_pdns_api_key "${PDNS_CREDS}" | cut -d'=' -f2)
DNS_SERVERS="sdns.iiko-systems.com mdns.iiko-systems.com"
LOG_FILE="/var/log/certbot_acme_zone.log"
TIMEISUP=10

log() {
    echo "[$(date '+%F %T')] $*" | tee -a "${LOG_FILE}" >&2
}

get_prefix() {
    case "$1" in
        iikoweb.ru|iikoweb.co.uk|eat-me.online|iiko.services|iiko.online|iiko.co.uk|iiko.it|iiko.cards|iiko.ru) echo "multi_" ;;
        iiko.biz) echo "" ;;
        *) echo "lets_" ;;
    esac
}

get_clean_domain() {
    echo "$1" | sed 's|^\*\.||'
}

cert_expiring_soon() {
    local cert_file="$1"
    [ -f "$cert_file" ] || return 1
    local expire_date
    expire_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
    [ -z "$expire_date" ] && return 1
    local expire_secs now_secs diff_days
    expire_secs=$(date -d "$expire_date" +%s)
    now_secs=$(date +%s)
    diff_days=$(( (expire_secs - now_secs) / 86400 ))
    [ "$diff_days" -lt "$TIMEISUP" ]
}

cleanup_old_lineages() {
    local domain="$1"
    local base_dir="/etc/letsencrypt/live/${domain}"
    local archive_base="/etc/letsencrypt/archive/${domain}"
    if [ -f "${base_dir}/fullchain.pem" ]; then
        if ! openssl x509 -in "${base_dir}/fullchain.pem" -noout -checkend 0 2>/dev/null; then
            log "⚠️  Протухший сертификат в ${base_dir}, удаляем..."
            rm -rf "${base_dir}" "${archive_base}" "/etc/letsencrypt/renewal/${domain}.conf"
        fi
    fi
    for suffix_dir in /etc/letsencrypt/live/${domain}-[0-9]*; do
        [ -d "$suffix_dir" ] || continue
        log "🗑️  Удаляем линейку: ${suffix_dir}"
        rm -rf "$suffix_dir"
        local suffix_name=$(basename "$suffix_dir")
        rm -rf "/etc/letsencrypt/archive/${suffix_name}" "/etc/letsencrypt/renewal/${suffix_name}.conf"
    done
}

save_to_webfolder() {
    local domain="$1"
    local prefix=$(get_prefix "${domain}")
    local clean=$(get_clean_domain "${domain}")
    local safe_domain=$(echo "${clean}" | sed 's|\.|_|g')
    local webfile="${WEBFOLDER}/${prefix}${safe_domain}.pem"
    local cert_dir="/etc/letsencrypt/live/${domain}"
    [ -f "${cert_dir}/fullchain.pem" ] || { log "ERROR: Нет fullchain.pem"; return 1; }
    cat "${cert_dir}/fullchain.pem" "${cert_dir}/privkey.pem" > "${webfile}"
    chmod 644 "${webfile}"
    log "✅ Сохранено: ${webfile}"
    return 0
}

update_md5sums() {
    if [ -d "${WEBFOLDER}" ]; then
        rm -f "${WEBFOLDER}/MD5SUMS"
        cd "${WEBFOLDER}" && for f in *.pem; do [ -f "$f" ] && md5sum "$f" >> MD5SUMS; done
        log "📝 MD5SUMS обновлён"
    fi
}

# Выпуск одного сертификата
issue_cert() {
    local ORIGINAL_DOMAIN="$1"
    local MODE="${2:-manual}"
    local CLEAN_DOMAIN=$(get_clean_domain "${ORIGINAL_DOMAIN}")

    log "🚀 Выпуск для: ${ORIGINAL_DOMAIN} (clean: ${CLEAN_DOMAIN}, mode: ${MODE})"

    [ "$MODE" = "manual" ] && cleanup_old_lineages "${CLEAN_DOMAIN}"

    local AUTH_HOOK="/tmp/certbot_auth_${CLEAN_DOMAIN}_$$.sh"
    local CLEANUP_HOOK="/tmp/certbot_cleanup_${CLEAN_DOMAIN}_$$.sh"
    local ZONE_ENCODED="=5Facme-challenge.${CLEAN_DOMAIN}."
    local RECORD_NAME="_acme-challenge.${CLEAN_DOMAIN}."

    # Формируем домены для certbot
    local CERTBOT_DOMAINS="-d ${CLEAN_DOMAIN}"
    if [ "$MODE" = "auto" ] || [[ "${ORIGINAL_DOMAIN}" == \*.* ]]; then
        CERTBOT_DOMAINS="${CERTBOT_DOMAINS} -d *.${CLEAN_DOMAIN}"
        log "🔑 Режим ${MODE}: добавляем wildcard -d *.${CLEAN_DOMAIN}"
    fi

    # === AUTH HOOK ===
    cat > "${AUTH_HOOK}" << AUTH_EOF
#!/bin/bash
set -e
API_KEY="${API_KEY}"
PDNS_URL="${PDNS_URL}"
ZONE_ENCODED="${ZONE_ENCODED}"
RECORD_NAME="${RECORD_NAME}"
DNS_SERVERS="${DNS_SERVERS}"
LOG_FILE="${LOG_FILE}"
TOKEN_FILE="/tmp/certbot_token_\${RECORD_NAME}.txt"

log() { echo "[$(date '+%F %T')] [AUTH] \$*" | tee -a "\${LOG_FILE}" >&2; }

# Фиксация токена (защита от повторных вызовов с другим токеном)
if [ -f "\${TOKEN_FILE}" ]; then
    EXISTING_TOKEN=\$(cat "\${TOKEN_FILE}")
    if [ "\${EXISTING_TOKEN}" != "\${CERTBOT_VALIDATION}" ]; then
        log "⚠️  Повторный вызов с другим токеном, используем первый: \${EXISTING_TOKEN}"
        CERTBOT_VALIDATION="\${EXISTING_TOKEN}"
    fi
else
    echo "\${CERTBOT_VALIDATION}" > "\${TOKEN_FILE}"
fi

log "API: Добавляем \${RECORD_NAME} с токеном [\${CERTBOT_VALIDATION}]"

# 🔧 Правильное построение JSON для PowerDNS
JSON_CONTENT="\"\\\\\"\${CERTBOT_VALIDATION}\\\\\"\""
JSON_PAYLOAD="{\"rrsets\":[{\"name\":\"\${RECORD_NAME}\",\"type\":\"TXT\",\"ttl\":60,\"changetype\":\"REPLACE\",\"records\":[{\"content\":\${JSON_CONTENT},\"disabled\":false}]}]}"

log "JSON: \${JSON_PAYLOAD}"

# Отправка с проверкой
RESP=\$(curl -s -w "HTTP:%{http_code}" -X PATCH \
    -H "X-API-Key: \${API_KEY}" \
    -H "Content-Type: application/json" \
    "\${PDNS_URL}/api/v1/servers/localhost/zones/\${ZONE_ENCODED}" \
    -d "\${JSON_PAYLOAD}")

HTTP_CODE=\$(echo "\${RESP}" | grep -o "HTTP:[0-9]*" | cut -d: -f2)
if [ "\${HTTP_CODE}" != "200" ] && [ "\${HTTP_CODE}" != "204" ]; then
    log "❌ API ошибка \${HTTP_CODE}: \${RESP}"
    exit 1
fi
log "✅ API: Запись отправлена (код \${HTTP_CODE})"

# 🔧 Проверка DNS: ждём появления записи на ВСЕХ серверах
max_wait=900; waited=0
log "DNS: Начинаем ожидание на всех серверах (\${DNS_SERVERS})..."
while [ \$waited -lt \$max_wait ]; do
    all_found=true
    for ns in \${DNS_SERVERS}; do
        raw=\$(dig @\${ns} \${RECORD_NAME} TXT +short +time=3 +tries=2 2>&1)
        clean=\$(echo "\$raw" | tr -d '"\r\n\t ' | xargs)
        [ -n "\$clean" ] && log "DNS: \${ns} → [\$clean]" || log "DNS: \${ns} → <пусто>"
        if [ "\$clean" != "\${CERTBOT_VALIDATION}" ]; then
            all_found=false
        fi
    done
    if \$all_found; then
        log "DNS: ✅ Запись подтверждена на всех серверах после \$((waited + 10)) сек"
        break
    fi
    sleep 10; waited=\$((waited + 10))
    [ \$((waited % 120)) -eq 0 ] && log "DNS: ⏳ Ждём... (\${waited}/\${max_wait})"
done

# 🔧 Увеличенная пауза для глобальной репликации (до серверов Let's Encrypt)
sleep 120
log "DNS: Готово, передаём управление certbot"
AUTH_EOF

    chmod +x "${AUTH_HOOK}"

    # === CLEANUP HOOK ===
    cat > "${CLEANUP_HOOK}" << CLEAN_EOF
#!/bin/bash
set -e
API_KEY="${API_KEY}"
PDNS_URL="${PDNS_URL}"
ZONE_ENCODED="${ZONE_ENCODED}"
RECORD_NAME="${RECORD_NAME}"
LOG_FILE="${LOG_FILE}"

log() { echo "[$(date '+%F %T')] [CLEANUP] \$*" | tee -a "\${LOG_FILE}" >&2; }

JSON_PAYLOAD="{\"rrsets\":[{\"name\":\"\${RECORD_NAME}\",\"type\":\"TXT\",\"changetype\":\"DELETE\"}]}"
RESP=\$(curl -s -w "HTTP:%{http_code}" -X PATCH \
    -H "X-API-Key: \${API_KEY}" \
    -H "Content-Type: application/json" \
    "\${PDNS_URL}/api/v1/servers/localhost/zones/\${ZONE_ENCODED}" \
    -d "\${JSON_PAYLOAD}")
HTTP_CODE=\$(echo "\${RESP}" | grep -o "HTTP:[0-9]*" | cut -d: -f2)
[ "\${HTTP_CODE}" != "200" ] && [ "\${HTTP_CODE}" != "204" ] && log "⚠️  Cleanup API код: \${HTTP_CODE}" || log "✅ Cleanup: запись удалена"

rm -f "/tmp/certbot_token_${RECORD_NAME}.txt"
CLEAN_EOF

    chmod +x "${CLEANUP_HOOK}"

    # Флаг --force-renewal только для ручного режима
    local FORCE_FLAG=""
    [ "$MODE" = "manual" ] && FORCE_FLAG="--force-renewal"

    if certbot certonly ${FORCE_FLAG} \
        --non-interactive \
        --key-type rsa \
        --manual \
        --preferred-challenges dns \
        --manual-auth-hook "${AUTH_HOOK}" \
        --manual-cleanup-hook "${CLEANUP_HOOK}" \
        --cert-name "${CLEAN_DOMAIN}" \
        --register-unsafely-without-email \
        --agree-tos \
        ${CERTBOT_DOMAINS}; then

        log "✅ Выпущен: ${CLEAN_DOMAIN}"
        save_to_webfolder "${CLEAN_DOMAIN}"
        rm -f "${AUTH_HOOK}" "${CLEANUP_HOOK}" "/tmp/certbot_token_${RECORD_NAME}.txt"
        return 0
    else
        log "❌ Ошибка: ${CLEAN_DOMAIN}"
        rm -f "${AUTH_HOOK}" "${CLEANUP_HOOK}" "/tmp/certbot_token_${RECORD_NAME}.txt"
        return 1
    fi
}

# === РЕЖИМ 1: Авто-сканирование (без аргумента) ===
if [ -z "$1" ]; then
    log "🔄 Режим автообновления..."
    LIVE_DIR="/etc/letsencrypt/live"
    [ -d "${LIVE_DIR}" ] || { log "ERROR: Нет live"; exit 1; }

    for dir_path in "${LIVE_DIR}"/*/; do
        dir=$(basename "$dir_path"); dir="${dir%/}"
        [[ "$dir" =~ -[0-9]+$ ]] && continue
        [[ "$dir" == \** ]] && continue
        cert_file="${dir_path}cert.pem"
        [ -f "$cert_file" ] || continue
        if cert_expiring_soon "$cert_file"; then
            log "⚠️  ${dir} истекает < ${TIMEISUP} дней"
            issue_cert "$dir" "auto" || log "❌ Не удалось: ${dir}"
        else
            prefix=$(get_prefix "$dir"); clean=$(get_clean_domain "$dir")
            safe=$(echo "$clean" | sed 's|\.|_|g'); webfile="${WEBFOLDER}/${prefix}${safe}.pem"
            if [ -f "$webfile" ]; then
                date_lets=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null)
                date_web=$(openssl x509 -in "$webfile" -noout -enddate 2>/dev/null)
                if [ "$date_lets" != "$date_web" ]; then
                    log "📦 Синхронизация: ${dir}"
                    cat "${dir_path}fullchain.pem" "${dir_path}privkey.pem" > "$webfile"
                fi
            fi
        fi
    done
    update_md5sums
    log "✅ Автообновление завершено"
    exit 0
fi

# === РЕЖИМ 2: Ручной запуск (с аргументом) ===
issue_cert "$1" "manual"
exit $?
