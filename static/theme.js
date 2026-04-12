// Переключение светлой/тёмной темы
(function() {
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    
    const savedTheme = localStorage.getItem('proib_theme');
    let isDark = false;
    if (savedTheme === 'dark') {
        isDark = true;
    } else if (savedTheme === 'light') {
        isDark = false;
    } else {
        isDark = false;
    }
    
    const root = document.documentElement;

    function setTheme(dark) {
        if (dark) {
            root.classList.add('dark');
            if (themeIcon) themeIcon.textContent = '🌙';
            localStorage.setItem('proib_theme', 'dark');
        } else {
            root.classList.remove('dark');
            if (themeIcon) themeIcon.textContent = '☀️';
            localStorage.setItem('proib_theme', 'light');
        }
    }
    
    setTheme(isDark);
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            setTheme(!root.classList.contains('dark'));
        });
    }
})();

// Фильтры с возможностью отмены
(function() {
    const urlParams = new URLSearchParams(window.location.search);
    let currentFilter = urlParams.get('filter');
    
    const filterChips = document.querySelectorAll('#filtersContainer .filter-chip');
    
    function updateFilter(filterValue) {
        const currentUrl = new URL(window.location.href);
        if (filterValue) {
            currentUrl.searchParams.set('filter', filterValue);
            currentUrl.searchParams.set('page', '1');
        } else {
            currentUrl.searchParams.delete('filter');
            currentUrl.searchParams.set('page', '1');
        }
        window.location.href = currentUrl.toString();
    }
    
    filterChips.forEach(chip => {
        const filterValue = chip.getAttribute('data-filter');
        if (currentFilter && filterValue === currentFilter) {
            chip.classList.add('active');
        }
        
        chip.addEventListener('click', function(e) {
            e.preventDefault();
            const clickedFilter = this.getAttribute('data-filter');
            
            if (this.classList.contains('active')) {
                updateFilter(null);
            } else {
                updateFilter(clickedFilter);
            }
        });
    });
})();

// обрабатываем карточку
document.addEventListener('DOMContentLoaded', function() {
    // Находим все карточки
    const cards = document.querySelectorAll('.vuln-card');
    
    cards.forEach(card => {
        card.addEventListener('click', function(e) {
            if (e.target.closest('form') || e.target.closest('button')) {
                return;
            }
            // Если кликнули не по ссылке (чтобы не срабатывало дважды)
            if (!e.target.closest('.detail-link')) {
                // Ищем ссылку внутри карточки
                const link = this.querySelector('.detail-link');
                if (link) {
                    window.location.href = link.href;
                }
            }
        });
    });
});

/** Экранирование для вставки произвольного текста в HTML (защита от DOM-XSS). */
function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/** Заголовок <strong> + перенос + текст без интерпретации как разметка. */
function setResultStrongLabelValue(el, label, value) {
    el.textContent = '';
    const strong = document.createElement('strong');
    strong.textContent = label;
    el.appendChild(strong);
    el.appendChild(document.createElement('br'));
    el.appendChild(document.createTextNode(value));
}

//генератор паролей 

function generatePassword() {
    const length = parseInt(document.getElementById('pwd-length').value) || 12;
    const useDigits = document.getElementById('pwd-digits').checked;
    const useSpecial = document.getElementById('pwd-special').checked;
    
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    if (useDigits) chars += '0123456789';
    if (useSpecial) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    const resultDiv = document.getElementById('password-result');
    resultDiv.textContent = password;
    
    const oldBtn = resultDiv.parentElement.querySelector('.copy-result-btn');
    if (oldBtn) oldBtn.remove();
    
    const copyBtn = document.createElement('button');
    copyBtn.textContent = '📋 Копировать';
    copyBtn.className = 'copy-result-btn';
    copyBtn.onclick = function(e) {
        e.stopPropagation();
        copyToClipboard(password, copyBtn);
    };
    resultDiv.parentElement.appendChild(copyBtn);
}

function copyToClipboard(text, button) {
    const originalText = button.innerHTML;
    
    // Способ 1: clipboard API
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopy(text, button, originalText);
        });
    } else {
        fallbackCopy(text, button, originalText);
    }
}

function fallbackCopy(text, button, originalText) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    
    try {
        document.execCommand('copy');
        button.innerHTML = '✅ Скопировано!';
        setTimeout(() => { button.innerHTML = originalText; }, 2000);
    } catch (err) {
        button.innerHTML = '❌ Ошибка';
        setTimeout(() => { button.innerHTML = originalText; }, 2000);
    }
    
    document.body.removeChild(textarea);
}

// делаем хеш текста

function computeHash() {
    let text = document.getElementById('hash-input').value;
    let algorithm = document.getElementById('hash-algorithm').value;
    let resultDiv = document.getElementById('hash-result');
    
    if (!text.trim()) {
        resultDiv.textContent = '❌ Введите текст';
        return;
    }
    
    if (typeof CryptoJS === 'undefined') {
        resultDiv.textContent = '❌ Библиотека не загружена';
        return;
    }
    
    let result = '';
    switch(algorithm) {
        case 'MD5':
            result = CryptoJS.MD5(text).toString();
            break;
        case 'SHA-1':
            result = CryptoJS.SHA1(text).toString();
            break;
        case 'SHA-256':
            result = CryptoJS.SHA256(text).toString();
            break;
        case 'SHA-512':
            result = CryptoJS.SHA512(text).toString();
            break;
        default:
            result = 'Неизвестный алгоритм';
    }
    
    resultDiv.textContent = result;
    
    // Добавляем кнопку копирования
    addCopyButton(resultDiv, result);
}

function addCopyButton(container, text) {
    const oldBtn = container.parentElement.querySelector('.copy-result-btn');
    if (oldBtn) oldBtn.remove();
    
    const copyBtn = document.createElement('button');
    copyBtn.textContent = '📋 Копировать';
    copyBtn.className = 'copy-result-btn';
    copyBtn.onclick = function(e) {
        e.stopPropagation();
        copyToClipboard(text, copyBtn);
    };
    container.parentElement.appendChild(copyBtn);
}

function copyToClipboard(text, button) {
    const originalText = button.innerHTML;
    
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopy(text, button, originalText);
        });
    } else {
        fallbackCopy(text, button, originalText);
    }
}

function fallbackCopy(text, button, originalText) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    button.innerHTML = '✅ Скопировано!';
    setTimeout(() => { button.innerHTML = originalText; }, 2000);
}

// ========== CSP (ПОДПИСЬ ДЛЯ СКРИПТОВ) ==========
function generateCspHash() {
    const htmlCode = document.getElementById('csp-input').value;
    const algorithm = document.getElementById('csp-algorithm').value;
    const resultDiv = document.getElementById('csp-result');
    
    if (!htmlCode.trim()) {
        resultDiv.textContent = '❌ Введите HTML-код';
        return;
    }
    
    // Ищем script и style теги через регулярные выражения
    const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    const styleRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi;
    
    const hashes = [];
    let match;
    
    // Обрабатываем script теги
    while ((match = scriptRegex.exec(htmlCode)) !== null) {
        let content = match[1].trim();
        if (content) {
            let hash = '';
            switch(algorithm) {
                case '256':
                    hash = CryptoJS.SHA256(content).toString(CryptoJS.enc.Base64);
                    break;
                case '384':
                    hash = CryptoJS.SHA384(content).toString(CryptoJS.enc.Base64);
                    break;
                case '512':
                    hash = CryptoJS.SHA512(content).toString(CryptoJS.enc.Base64);
                    break;
            }
            hashes.push(`'sha${algorithm}-${hash}'`);
        }
    }
    
    // Обрабатываем style теги
    while ((match = styleRegex.exec(htmlCode)) !== null) {
        let content = match[1].trim();
        if (content) {
            let hash = '';
            switch(algorithm) {
                case '256':
                    hash = CryptoJS.SHA256(content).toString(CryptoJS.enc.Base64);
                    break;
                case '384':
                    hash = CryptoJS.SHA384(content).toString(CryptoJS.enc.Base64);
                    break;
                case '512':
                    hash = CryptoJS.SHA512(content).toString(CryptoJS.enc.Base64);
                    break;
            }
            hashes.push(`'sha${algorithm}-${hash}'`);
        }
    }
    
    if (hashes.length > 0) {
        const resultText = hashes.join('\n');
        resultDiv.textContent = resultText;
        
        // Добавляем кнопку копирования
        const oldBtn = resultDiv.parentElement.querySelector('.copy-result-btn');
        if (oldBtn) oldBtn.remove();
        
        const copyBtn = document.createElement('button');
        copyBtn.textContent = '📋 Копировать все';
        copyBtn.className = 'copy-result-btn';
        copyBtn.style.marginTop = '12px';
        copyBtn.style.width = '100%';
        copyBtn.onclick = function(e) {
            e.stopPropagation();
            copyToClipboardCsp(resultText, copyBtn);
        };
        resultDiv.parentElement.appendChild(copyBtn);
    } else {
        resultDiv.textContent =
            '⚠️ В коде не найдено встроенных тегов <script> или <style>';
    }
}

function copyToClipboardCsp(text, button) {
    const originalText = button.innerHTML;
    
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyCsp(text, button, originalText);
        });
    } else {
        fallbackCopyCsp(text, button, originalText);
    }
}

function fallbackCopyCsp(text, button, originalText) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    button.innerHTML = '✅ Скопировано!';
    setTimeout(() => { button.innerHTML = originalText; }, 2000);
}


// ========== КОДИРОВАНИЕ / ДЕКОДИРОВАНИЕ BASE64 ==========
function encodeBase64() {
    let input = document.getElementById('base64-input').value;
    let resultDiv = document.getElementById('base64-result');
    let container = document.getElementById('base64-result-container');
    
    if (!input.trim()) {
        resultDiv.textContent = '❌ Введите текст';
        return;
    }
    try {
        let encoded = btoa(unescape(encodeURIComponent(input)));
        setResultStrongLabelValue(resultDiv, 'Base64:', encoded);
        addCopyButtonToBase64(container, encoded);
    } catch (e) {
        resultDiv.textContent =
            '❌ Ошибка кодирования: ' + (e && e.message != null ? String(e.message) : '');
    }
}

function decodeBase64() {
    let input = document.getElementById('base64-input').value;
    let resultDiv = document.getElementById('base64-result');
    let container = document.getElementById('base64-result-container');
    
    if (!input.trim()) {
        resultDiv.textContent = '❌ Введите Base64 строку';
        return;
    }
    try {
        let decoded = decodeURIComponent(escape(atob(input)));
        setResultStrongLabelValue(resultDiv, 'Декодировано:', decoded);
        addCopyButtonToBase64(container, decoded);
    } catch (e) {
        resultDiv.textContent = '❌ Ошибка декодирования: неверный формат Base64';
    }
}

function clearBase64() {
    document.getElementById('base64-input').value = '';
    document.getElementById('base64-result').textContent =
        'Нажмите кнопку кодирования или декодирования';
    
    // Удаляем кнопку копирования
    const oldBtn = document.getElementById('base64-result-container').querySelector('.copy-result-btn');
    if (oldBtn) oldBtn.remove();
}

// Добавление кнопки копирования для Base64
function addCopyButtonToBase64(container, text) {
    const oldBtn = container.querySelector('.copy-result-btn');
    if (oldBtn) oldBtn.remove();
    
    const copyBtn = document.createElement('button');
    copyBtn.textContent = '📋 Копировать результат';
    copyBtn.className = 'copy-result-btn';
    copyBtn.style.marginTop = '12px';
    copyBtn.style.width = '100%';
    copyBtn.onclick = function(e) {
        e.stopPropagation();
        copyToClipboardBase64(text, copyBtn);
    };
    container.appendChild(copyBtn);
}

function copyToClipboardBase64(text, button) {
    const originalText = button.innerHTML;
    
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyBase64(text, button, originalText);
        });
    } else {
        fallbackCopyBase64(text, button, originalText);
    }
}

function fallbackCopyBase64(text, button, originalText) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    button.innerHTML = '✅ Скопировано!';
    setTimeout(() => { button.innerHTML = originalText; }, 2000);
}

// ========== АНАЛИЗ JWT ТОКЕНОВ ==========
function analyzeJwt() {
    let token = document.getElementById('jwt-input').value.trim();
    let resultDiv = document.getElementById('jwt-result-section');
    let resultText = document.getElementById('jwt-result');
    
    if (!token) {
        resultText.textContent = 'Введите JWT токен';
        resultDiv.style.display = 'block';
        return;
    }
    
    // Разделяем токен на части
    let parts = token.split('.');
    if (parts.length !== 3) {
        resultText.textContent =
            '❌ Неверный формат JWT. Ожидается три части, разделённые точками.';
        resultDiv.style.display = 'block';
        return;
    }
    
    try {
        // Декодируем header и payload (Base64Url → Base64 → JSON)
        let header = JSON.parse(base64UrlDecode(parts[0]));
        let payload = JSON.parse(base64UrlDecode(parts[1]));
        let signature = parts[2];
        
        // Проверяем срок действия
        let expInfo = '';
        if (payload.exp) {
            let expDate = new Date(payload.exp * 1000);
            let now = new Date();
            const expStr = escapeHtml(expDate.toLocaleString());
            if (expDate < now) {
                expInfo = `<span style="color: #dc3545;">⚠️ Токен ПРОСРОЧЕН (истёк ${expStr})</span>`;
            } else {
                expInfo = `<span style="color: #28a745;">✅ Токен действителен до ${expStr}</span>`;
            }
        } else {
            expInfo = `<span style="color: #ffc107;">⚠️ Поле exp (срок действия) отсутствует</span>`;
        }
        
        const headerJson = escapeHtml(JSON.stringify(header, null, 2));
        const payloadJson = escapeHtml(JSON.stringify(payload, null, 2));
        const signatureEsc = escapeHtml(signature);
        
        let html = `
            <div style="margin-bottom: 15px;">
                <strong>🔹 Заголовок (Header):</strong>
                <pre style="background: var(--bg-meta); padding: 10px; border-radius: 8px; overflow-x: auto;">${headerJson}</pre>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>🔹 Полезная нагрузка (Payload):</strong>
                <pre style="background: var(--bg-meta); padding: 10px; border-radius: 8px; overflow-x: auto;">${payloadJson}</pre>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>🔹 Подпись (Signature):</strong>
                <pre style="background: var(--bg-meta); padding: 10px; border-radius: 8px; overflow-x: auto;">${signatureEsc}</pre>
            </div>
            <div style="margin-top: 15px; padding: 10px; background: var(--bg-input); border-radius: 8px;">
                ${expInfo}
            </div>
        `;
        
        resultText.innerHTML = html;
        resultDiv.style.display = 'block';
        
    } catch (e) {
        resultText.textContent =
            '❌ Ошибка декодирования: ' + (e && e.message != null ? String(e.message) : '');
        resultDiv.style.display = 'block';
    }
}

function clearJwt() {
    document.getElementById('jwt-input').value = '';
    document.getElementById('jwt-result-section').style.display = 'none';
    document.getElementById('jwt-result').textContent = '';
}

// Функция декодирования Base64Url (JWT использует Base64Url без = и с -_ вместо +/)
function base64UrlDecode(str) {
    // Заменяем Base64Url на стандартный Base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    // Добавляем padding, если нужно
    while (base64.length % 4) {
        base64 += '=';
    }
    // Декодируем Base64 в строку
    return atob(base64);
}


// ========== ДЕКОДИРОВАНИЕ URL ==========
function encodeUrl() {
    let input = document.getElementById('url-input').value;
    let resultDiv = document.getElementById('url-result');
    let container = document.getElementById('url-result-container');
    
    if (!input.trim()) {
        resultDiv.textContent = '❌ Введите текст';
        return;
    }
    try {
        let encoded = encodeURIComponent(input);
        setResultStrongLabelValue(resultDiv, 'Закодированная строка:', encoded);
        addCopyButtonToUrl(container, encoded);
    } catch (e) {
        resultDiv.textContent =
            '❌ Ошибка кодирования: ' + (e && e.message != null ? String(e.message) : '');
    }
}

function decodeUrl() {
    let input = document.getElementById('url-input').value;
    let resultDiv = document.getElementById('url-result');
    let container = document.getElementById('url-result-container');
    
    if (!input.trim()) {
        resultDiv.textContent = '❌ Введите URL строку';
        return;
    }
    try {
        let decoded = decodeURIComponent(input);
        setResultStrongLabelValue(resultDiv, 'Декодированная строка:', decoded);
        addCopyButtonToUrl(container, decoded);
    } catch (e) {
        resultDiv.textContent = '❌ Ошибка декодирования: неверный формат URL';
    }
}

function clearUrl() {
    document.getElementById('url-input').value = '';
    document.getElementById('url-result').textContent =
        'Нажмите кнопку кодирования или декодирования';
    
    // Удаляем кнопку копирования
    const oldBtn = document.getElementById('url-result-container').querySelector('.copy-result-btn');
    if (oldBtn) oldBtn.remove();
}

// Добавление кнопки копирования для URL
function addCopyButtonToUrl(container, text) {
    const oldBtn = container.querySelector('.copy-result-btn');
    if (oldBtn) oldBtn.remove();
    
    const copyBtn = document.createElement('button');
    copyBtn.textContent = '📋 Копировать результат';
    copyBtn.className = 'copy-result-btn';
    copyBtn.style.marginTop = '12px';
    copyBtn.style.width = '100%';
    copyBtn.onclick = function(e) {
        e.stopPropagation();
        copyToClipboardUrl(text, copyBtn);
    };
    container.appendChild(copyBtn);
}

function copyToClipboardUrl(text, button) {
    const originalText = button.innerHTML;
    
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyUrl(text, button, originalText);
        });
    } else {
        fallbackCopyUrl(text, button, originalText);
    }
}

function fallbackCopyUrl(text, button, originalText) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    button.innerHTML = '✅ Скопировано!';
    setTimeout(() => { button.innerHTML = originalText; }, 2000);
}


// ========== WHOIS КОПИРОВАНИЕ ==========
function copyWhoisResult() {
    const resultText = document.getElementById('whois-result')?.innerText;
    const button = event.target;
    
    if (!resultText) {
        showToast('Нет данных для копирования');
        return;
    }
    
    const originalText = button.innerHTML;
    
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText, button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText, button, originalText);
    }
}

function fallbackCopyWhois(text, button, originalText) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    button.innerHTML = '✅ Скопировано!';
    setTimeout(() => { button.innerHTML = originalText; }, 2000);
}

// ========== ПРОВЕРКА URL — раскрытие полного списка поставщиков ==========
function toggleVtProvidersMore() {
    const more = document.getElementById('vt-providers-more');
    const btn = document.getElementById('vt-providers-toggle');
    if (!more || !btn) return;
    const open = more.style.display === 'table-row-group';
    more.style.display = open ? 'none' : 'table-row-group';
    btn.textContent = open ? 'Показать полный список' : 'Скрыть полный список';
}

// ========== ПРОВЕРКА URL — копирование сводки ==========
function copyVtUrlResult() {
    const resultText = document.getElementById('vt-url-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

// ========== ПРОВЕРКА ФАЙЛА — отправка (долгое ожидание VirusTotal) ==========
function vtFileFormSubmit(form) {
    const hint = document.getElementById('vt-file-submit-hint');
    const btn = form.querySelector('#vt-file-submit-btn') || form.querySelector('button[type="submit"]');
    if (hint) {
        hint.hidden = false;
    }
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Отправлено… ждите (1–5 мин)';
    }
    return true;
}

// ========== АНАЛИЗАТОР ДОВЕРИЯ — долгое ожидание (как у проверки URL/файла) ==========
function trustScoreFormSubmit(form) {
    const hint = document.getElementById('trust-score-submit-hint');
    const btn = document.getElementById('trust-score-submit-btn');
    if (hint) {
        hint.hidden = false;
    }
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Ожидайте… идёт анализ';
    }
    return true;
}

// ========== ПОИСК ДОМЕНОВ ОРГАНИЗАЦИИ — долгое ожидание (как у проверки файла) ==========
function orgDomainFormSubmit(form) {
    const hint = document.getElementById('org-domain-submit-hint');
    const btn = document.getElementById('org-domain-submit-btn');
    if (hint) {
        hint.hidden = false;
    }
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Подождите… идёт запрос';
    }
    return true;
}

function initOrgDomainDadataSuggest() {
    const input = document.getElementById('org-domain-input');
    const list = document.getElementById('org-domain-suggest-list');
    if (!input || !list) {
        return;
    }

    let timer = null;
    let hideTimer = null;

    function clearSuggestListLayout() {
        ['position', 'left', 'top', 'width', 'maxHeight', 'zIndex', 'right', 'bottom'].forEach(function (k) {
            list.style[k] = '';
        });
    }

    /** Список поверх нижнего таб-бара; высота — до панели, прокрутка внутри списка */
    function positionOrgDomainSuggestList() {
        if (list.hidden) {
            return;
        }
        const r = input.getBoundingClientRect();
        const tabReserve = 96;
        const spaceBelow = window.innerHeight - r.bottom - 4 - tabReserve;
        const maxH = Math.max(120, Math.min(320, spaceBelow));
        list.style.position = 'fixed';
        list.style.left = r.left + 'px';
        list.style.top = r.bottom + 4 + 'px';
        list.style.width = r.width + 'px';
        list.style.maxHeight = maxH + 'px';
        list.style.zIndex = '10050';
        list.style.right = 'auto';
        list.style.bottom = 'auto';
    }

    function hideList() {
        list.hidden = true;
        list.innerHTML = '';
        clearSuggestListLayout();
    }

    function onSuggestReposition() {
        if (!list.hidden) {
            positionOrgDomainSuggestList();
        }
    }

    window.addEventListener('scroll', onSuggestReposition, true);
    window.addEventListener('resize', onSuggestReposition);

    input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') {
            hideList();
        }
    });

    input.addEventListener('blur', function () {
        hideTimer = setTimeout(hideList, 180);
    });

    input.addEventListener('focus', function () {
        if (hideTimer) {
            clearTimeout(hideTimer);
        }
        if (!list.hidden) {
            positionOrgDomainSuggestList();
        }
    });

    input.addEventListener('input', function () {
        clearTimeout(timer);
        timer = setTimeout(runOrgDomainSuggest, 300);
    });

    function applySuggestion(s) {
        const inn = s.inn != null ? String(s.inn).trim() : '';
        let v = '';
        if (/^(?:\d{10}|\d{12})$/.test(inn)) {
            v = inn;
        } else if (s.name_short) {
            v = s.name_short;
        } else if (s.name_full) {
            v = s.name_full;
        } else if (s.name) {
            v = s.name;
        } else if (s.value) {
            v = s.value;
        }
        if (v) {
            input.value = v;
        }
    }

    async function runOrgDomainSuggest() {
        const q = input.value.trim();
        if (q.length < 2) {
            hideList();
            return;
        }
        try {
            const csrfEl = document.querySelector('meta[name="csrf-token"]');
            const csrf = csrfEl ? csrfEl.getAttribute('content') : '';
            const headers = { 'Content-Type': 'application/json' };
            if (csrf) {
                headers['X-CSRFToken'] = csrf;
            }
            const r = await fetch('/api/dadata/party-suggest', {
                method: 'POST',
                headers,
                body: JSON.stringify({ q }),
            });
            const data = await r.json();
            if (data.error || !(data.suggestions && data.suggestions.length)) {
                hideList();
                return;
            }
            list.innerHTML = '';
            data.suggestions.forEach(function (s) {
                const li = document.createElement('li');
                li.className = 'org-domain-suggest-item';
                li.setAttribute('role', 'option');
                li.textContent = s.label || s.value || '';
                li.addEventListener('mousedown', function (ev) {
                    ev.preventDefault();
                    if (hideTimer) {
                        clearTimeout(hideTimer);
                    }
                    applySuggestion(s);
                    hideList();
                    input.focus();
                });
                list.appendChild(li);
            });
            list.hidden = false;
            positionOrgDomainSuggestList();
        } catch (e) {
            hideList();
        }
    }
}

// ========== ПРОВЕРКА ФАЙЛА — раскрытие полного списка поставщиков ==========
function toggleVtFileProvidersMore() {
    const more = document.getElementById('vt-file-providers-more');
    const btn = document.getElementById('vt-file-providers-toggle');
    if (!more || !btn) return;
    const open = more.style.display === 'table-row-group';
    more.style.display = open ? 'none' : 'table-row-group';
    btn.textContent = open ? 'Показать полный список' : 'Скрыть полный список';
}

// ========== ПРОВЕРКА ФАЙЛА — копирование сводки ==========
function copyVtFileResult() {
    const resultText = document.getElementById('vt-file-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

// ========== DNS LOOKUP — копирование сводки ==========
function copyDnsLookupResult() {
    const resultText = document.getElementById('dns-lookup-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

// ========== REVERSE DNS — копирование сводки ==========
function copyReverseDnsResult() {
    const resultText = document.getElementById('reverse-dns-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

// ========== ГЕОЛОКАЦИЯ IP — копирование сводки ==========
function copyIpGeoResult(sourceId, btn) {
    const id = sourceId || 'ip-geo-copy-source';
    const resultText = document.getElementById(id)?.innerText;
    const button = btn || (typeof event !== 'undefined' ? event.currentTarget : null);

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }
    if (!button) {
        showToast('Не удалось определить кнопку');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

function copyHttpHeadersSummary() {
    const resultText = document.getElementById('http-hdr-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

function copySslSummary() {
    const resultText = document.getElementById('ssl-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

function copyOrgDomainResult() {
    const resultText = document.getElementById('org-domain-copy-source')?.innerText;
    const button = event.target;

    if (!resultText || !resultText.trim()) {
        showToast('Нет данных для копирования');
        return;
    }

    const originalText = button.innerHTML;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(resultText.trim()).then(() => {
            button.innerHTML = '✅ Скопировано!';
            setTimeout(() => { button.innerHTML = originalText; }, 2000);
        }).catch(() => {
            fallbackCopyWhois(resultText.trim(), button, originalText);
        });
    } else {
        fallbackCopyWhois(resultText.trim(), button, originalText);
    }
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.position = 'fixed';
    toast.style.bottom = '80px';
    toast.style.left = '50%';
    toast.style.transform = 'translateX(-50%)';
    toast.style.background = 'var(--accent-red)';
    toast.style.color = 'white';
    toast.style.padding = '10px 20px';
    toast.style.borderRadius = '40px';
    toast.style.fontSize = '14px';
    toast.style.zIndex = '1000';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2000);
}

function escapeHtmlIpGeo(s) {
    return escapeHtml(s);
}

function ipGeoHostingBadgeHtml(hosting) {
    if (hosting === true) {
        return '<span class="ip-geo-badge ip-geo-badge-yes">Вероятно да</span>';
    }
    if (hosting === false) {
        return '<span class="ip-geo-badge ip-geo-badge-no">Нет</span>';
    }
    return '<span class="ip-geo-badge ip-geo-badge-unk">—</span>';
}

/**
 * Разметка карточки геолокации по JSON 2ip.io (без заголовка секции — он в шаблоне).
 */
function buildIpGeoResultHtmlFromJson(data, copyElId) {
    const emoji = escapeHtmlIpGeo(data.emoji || '🌐');
    const country = escapeHtmlIpGeo(data.country || '—');
    const code = escapeHtmlIpGeo(data.code || '—');
    const city = escapeHtmlIpGeo(data.city || '—');
    const region = escapeHtmlIpGeo(data.region || '—');
    const tz = escapeHtmlIpGeo(data.timezone || '—');
    const ip = escapeHtmlIpGeo(data.ip || '—');
    const lat = data.lat;
    const lon = data.lon;
    const coords =
        lat && lon
            ? `${escapeHtmlIpGeo(lat)}, ${escapeHtmlIpGeo(lon)}`
            : '—';
    const mapLink =
        lat && lon
            ? `<a class="ip-geo-map-link" href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(
                  String(lat),
              )}&mlon=${encodeURIComponent(String(lon))}&zoom=11" target="_blank" rel="noopener noreferrer">Открыть на карте ↗</a>`
            : '';
    const asn = data.asn || {};
    const asId = asn.id != null && asn.id !== '' ? `AS${escapeHtmlIpGeo(asn.id)}` : '—';
    const asName = escapeHtmlIpGeo(asn.name || '—');
    const copyPlain = [
        `IP: ${data.ip || ''}`,
        `Страна: ${data.country || ''} (${data.code || ''})`,
        `Регион: ${data.region || ''}`,
        `Город: ${data.city || ''}`,
        `Координаты: ${lat || ''}, ${lon || ''}`,
        `Часовой пояс: ${data.timezone || ''}`,
        `ASN: ${asn.id != null && asn.id !== '' ? `AS${asn.id}` : '—'} — ${asn.name || ''}`,
        `Хостинг: ${
            asn.hosting === true ? 'да' : asn.hosting === false ? 'нет' : '—'
        }`,
    ].join('\n');

    return (
        `<div class="ip-geo-result-wrap">` +
        `<div class="ip-geo-hero">` +
        `<span class="ip-geo-hero-emoji" aria-hidden="true">${emoji}</span>` +
        `<div class="ip-geo-hero-text">` +
        `<div class="ip-geo-country">${country}</div>` +
        `<div class="ip-geo-code-line">` +
        `<span class="ip-geo-chip">ISO ${code}</span> ${mapLink}` +
        `</div></div></div>` +
        `<div class="ip-geo-grid">` +
        `<div class="ip-geo-tile"><div class="ip-geo-tile-label">IP</div><div class="ip-geo-tile-value ip-geo-mono">${ip}</div></div>` +
        `<div class="ip-geo-tile"><div class="ip-geo-tile-label">Город / населённый пункт</div><div class="ip-geo-tile-value">${city}</div></div>` +
        `<div class="ip-geo-tile"><div class="ip-geo-tile-label">Регион</div><div class="ip-geo-tile-value">${region}</div></div>` +
        `<div class="ip-geo-tile"><div class="ip-geo-tile-label">Координаты</div><div class="ip-geo-tile-value ip-geo-mono">${coords}</div></div>` +
        `<div class="ip-geo-tile ip-geo-tile-wide"><div class="ip-geo-tile-label">Часовой пояс (IANA)</div><div class="ip-geo-tile-value ip-geo-mono">${tz}</div></div>` +
        `</div>` +
        `<div class="ip-geo-asn-card">` +
        `<div class="ip-geo-asn-title"><span class="ip-geo-asn-icon">🔗</span> Автономная система (ASN)</div>` +
        `<div class="ip-geo-asn-body">` +
        `<div class="ip-geo-asn-row"><span class="ip-geo-asn-k">Номер AS</span><span class="ip-geo-asn-v ip-geo-mono">${asId}</span></div>` +
        `<div class="ip-geo-asn-row"><span class="ip-geo-asn-k">Имя</span><span class="ip-geo-asn-v">${asName}</span></div>` +
        `<div class="ip-geo-asn-row ip-geo-asn-hosting"><span class="ip-geo-asn-k">Хостинг / датацентр</span>${ipGeoHostingBadgeHtml(asn.hosting)}</div>` +
        `</div></div>` +
        `<div id="${copyElId}" class="ip-geo-copy-hidden" aria-hidden="true">${escapeHtmlIpGeo(copyPlain)}</div>` +
        `<button type="button" onclick="copyIpGeoResult('${copyElId}', this)" class="copy-result-btn ip-geo-copy-btn">📋 Копировать сводку</button>` +
        `<p class="ip-geo-disclaimer">Данные справочные; при VPN и прокси местоположение может не совпадать с реальным. Не используйте для идентификации личности.</p>` +
        `</div>`
    );
}

function initIpGeoMyClientFetch() {
    const root = document.getElementById('ip-geo-my-client-root');
    if (!root) return;
    const url = root.getAttribute('data-geo-url');
    if (!url) {
        root.innerHTML =
            '<div class="result-card ip-geo-error-card"><p class="ip-geo-error-text">Не настроен URL геосервиса.</p></div>';
        return;
    }
    fetch(url, { method: 'GET', mode: 'cors', credentials: 'omit' })
        .then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (data) {
            root.innerHTML = buildIpGeoResultHtmlFromJson(data, 'ip-geo-my-copy-source');
        })
        .catch(function () {
            root.innerHTML =
                '<div class="result-card ip-geo-error-card"><p class="ip-geo-error-text">Не удалось загрузить данные с 2ip.io из браузера (сеть, блокировка CORS или расширения). Укажите свой IP во втором блоке вручную или откройте <a href="https://api.2ip.io/" target="_blank" rel="noopener noreferrer">api.2ip.io</a> в новой вкладке.</p></div>';
        });
}

document.addEventListener('DOMContentLoaded', function () {
    initOrgDomainDadataSuggest();
    initIpGeoMyClientFetch();
});