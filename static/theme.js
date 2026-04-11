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
    
    function setTheme(dark) {
        if (dark) {
            document.body.classList.add('dark');
            if (themeIcon) themeIcon.textContent = '🌙';
            localStorage.setItem('proib_theme', 'dark');
        } else {
            document.body.classList.remove('dark');
            if (themeIcon) themeIcon.textContent = '☀️';
            localStorage.setItem('proib_theme', 'light');
        }
    }
    
    setTheme(isDark);
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            setTheme(!document.body.classList.contains('dark'));
        });
    }
})();

// Фильтры с возможностью отмены
(function() {
    const urlParams = new URLSearchParams(window.location.search);
    let currentFilter = urlParams.get('filter');
    
    const filterChips = document.querySelectorAll('.filter-chip');
    
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
        resultDiv.innerHTML = '❌ Введите HTML-код';
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
        resultDiv.innerHTML = resultText;
        
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
        resultDiv.innerHTML = '⚠️ В коде не найдено встроенных тегов &lt;script&gt; или &lt;style&gt;';
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
        resultDiv.innerHTML = '❌ Введите текст';
        return;
    }
    try {
        let encoded = btoa(unescape(encodeURIComponent(input)));
        resultDiv.innerHTML = `<strong>Base64:</strong><br>${encoded}`;
        addCopyButtonToBase64(container, encoded);
    } catch (e) {
        resultDiv.innerHTML = '❌ Ошибка кодирования: ' + e.message;
    }
}

function decodeBase64() {
    let input = document.getElementById('base64-input').value;
    let resultDiv = document.getElementById('base64-result');
    let container = document.getElementById('base64-result-container');
    
    if (!input.trim()) {
        resultDiv.innerHTML = '❌ Введите Base64 строку';
        return;
    }
    try {
        let decoded = decodeURIComponent(escape(atob(input)));
        resultDiv.innerHTML = `<strong>Декодировано:</strong><br>${decoded}`;
        addCopyButtonToBase64(container, decoded);
    } catch (e) {
        resultDiv.innerHTML = '❌ Ошибка декодирования: неверный формат Base64';
    }
}

function clearBase64() {
    document.getElementById('base64-input').value = '';
    document.getElementById('base64-result').innerHTML = 'Нажмите кнопку кодирования или декодирования';
    
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
        resultText.innerHTML = 'Введите JWT токен';
        resultDiv.style.display = 'block';
        return;
    }
    
    // Разделяем токен на части
    let parts = token.split('.');
    if (parts.length !== 3) {
        resultText.innerHTML = '❌ Неверный формат JWT. Ожидается три части, разделённые точками.';
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
            if (expDate < now) {
                expInfo = `<span style="color: #dc3545;">⚠️ Токен ПРОСРОЧЕН (истёк ${expDate.toLocaleString()})</span>`;
            } else {
                expInfo = `<span style="color: #28a745;">✅ Токен действителен до ${expDate.toLocaleString()}</span>`;
            }
        } else {
            expInfo = `<span style="color: #ffc107;">⚠️ Поле exp (срок действия) отсутствует</span>`;
        }
        
        // Формируем вывод
        let html = `
            <div style="margin-bottom: 15px;">
                <strong>🔹 Заголовок (Header):</strong>
                <pre style="background: var(--bg-meta); padding: 10px; border-radius: 8px; overflow-x: auto;">${JSON.stringify(header, null, 2)}</pre>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>🔹 Полезная нагрузка (Payload):</strong>
                <pre style="background: var(--bg-meta); padding: 10px; border-radius: 8px; overflow-x: auto;">${JSON.stringify(payload, null, 2)}</pre>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>🔹 Подпись (Signature):</strong>
                <pre style="background: var(--bg-meta); padding: 10px; border-radius: 8px; overflow-x: auto;">${signature}</pre>
            </div>
            <div style="margin-top: 15px; padding: 10px; background: var(--bg-input); border-radius: 8px;">
                ${expInfo}
            </div>
        `;
        
        resultText.innerHTML = html;
        resultDiv.style.display = 'block';
        
    } catch (e) {
        resultText.innerHTML = `❌ Ошибка декодирования: ${e.message}`;
        resultDiv.style.display = 'block';
    }
}

function clearJwt() {
    document.getElementById('jwt-input').value = '';
    document.getElementById('jwt-result-section').style.display = 'none';
    document.getElementById('jwt-result').innerHTML = '';
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
    if (!input.trim()) {
        document.getElementById('url-result').innerText = 'Введите текст';
        return;
    }
    try {
        let encoded = encodeURIComponent(input);
        document.getElementById('url-result').innerHTML = `<strong>Закодированная строка:</strong><br>${encoded}`;
    } catch (e) {
        document.getElementById('url-result').innerText = 'Ошибка кодирования: ' + e.message;
    }
}

function decodeUrl() {
    let input = document.getElementById('url-input').value;
    if (!input.trim()) {
        document.getElementById('url-result').innerText = 'Введите URL строку';
        return;
    }
    try {
        let decoded = decodeURIComponent(input);
        document.getElementById('url-result').innerHTML = `<strong>Декодированная строка:</strong><br>${decoded}`;
    } catch (e) {
        document.getElementById('url-result').innerText = 'Ошибка декодирования: неверный формат URL';
    }
}

function clearUrl() {
    document.getElementById('url-input').value = '';
    document.getElementById('url-result').innerHTML = 'Нажмите кнопку кодирования или декодирования';
}

// ========== ДЕКОДИРОВАНИЕ URL ==========
function encodeUrl() {
    let input = document.getElementById('url-input').value;
    let resultDiv = document.getElementById('url-result');
    let container = document.getElementById('url-result-container');
    
    if (!input.trim()) {
        resultDiv.innerHTML = '❌ Введите текст';
        return;
    }
    try {
        let encoded = encodeURIComponent(input);
        resultDiv.innerHTML = `<strong>Закодированная строка:</strong><br>${encoded}`;
        addCopyButtonToUrl(container, encoded);
    } catch (e) {
        resultDiv.innerHTML = '❌ Ошибка кодирования: ' + e.message;
    }
}

function decodeUrl() {
    let input = document.getElementById('url-input').value;
    let resultDiv = document.getElementById('url-result');
    let container = document.getElementById('url-result-container');
    
    if (!input.trim()) {
        resultDiv.innerHTML = '❌ Введите URL строку';
        return;
    }
    try {
        let decoded = decodeURIComponent(input);
        resultDiv.innerHTML = `<strong>Декодированная строка:</strong><br>${decoded}`;
        addCopyButtonToUrl(container, decoded);
    } catch (e) {
        resultDiv.innerHTML = '❌ Ошибка декодирования: неверный формат URL';
    }
}

function clearUrl() {
    document.getElementById('url-input').value = '';
    document.getElementById('url-result').innerHTML = 'Нажмите кнопку кодирования или декодирования';
    
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