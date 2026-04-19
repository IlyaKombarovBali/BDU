import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "site.db"
GLOSSARY_PATH = ROOT / "owasp" / "Glossary.html"

CAT_AUTH = "Основы контроля доступа и аутентификации"
CAT_WEB = "Защита от веб-атак (OWASP Top 10)"
CAT_DEV = "Безопасность разработки и CI/CD"
CAT_MOD = "Современные угрозы и методы защиты"
CAT_FW = "Безопасность популярных технологий и фреймворков"
CAT_CLOUD = "Безопасность облачных и контейнерных сред"
CAT_PLAT = "Безопасность специфичных платформ и устройств"
CAT_GEN = "Общие термины и методология"

META = {
    "cheatsheets/AJAX_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "Рекомендации по безопасности асинхронных запросов XMLHttpRequest и Fetch. Снижение рисков XSS, CSRF и утечек данных при обмене с сервером.",
    ),
    "cheatsheets/Abuse_Case_Cheat_Sheet.html": (
        CAT_PLAT,
        "Формулирование сценариев злоупотребления при моделировании угроз. Помогает выявлять злоупотребления функциональностью до реализации.",
    ),
    "cheatsheets/Access_Control_Cheat_Sheet.html": (
        CAT_AUTH,
        "Принципы проектирования и проверки контроля доступа: разделение привилегий, принцип наименьших привилегий, защита от обхода проверок.",
    ),
    "cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html": (
        CAT_DEV,
        "Методы инвентаризации и оценки поверхности атаки приложения и инфраструктуры для приоритизации мер защиты.",
    ),
    "cheatsheets/Authentication_Cheat_Sheet.html": (
        CAT_AUTH,
        "Практики надёжной аутентификации пользователей: учётные данные, политики паролей, защита механизма входа от перебора и обхода.",
    ),
    "cheatsheets/Authorization_Cheat_Sheet.html": (
        CAT_AUTH,
        "Разграничение прав после аутентификации: проверка полномочий на каждой операции, роли, защита от эскалации привилегий.",
    ),
    "cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html": (
        CAT_AUTH,
        "Автоматизация проверок авторизации в тестах и CI: типовые ошибки, негативные сценарии и интеграция в конвейер.",
    ),
    "cheatsheets/Automotive_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "Особенности ИБ автомобильных и связанных систем: сегментация шин, OTA, угрозы для ECU и внешних интерфейсов.",
    ),
    "cheatsheets/Bean_Validation_Cheat_Sheet.html": (
        CAT_FW,
        "Безопасное использование Bean Validation (Jakarta/Java) для ограничения входных данных и снижения риска инъекций и некорректной бизнес-логики.",
    ),
    "cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html": (
        CAT_PLAT,
        "Типовые уязвимости расширений браузера: XSS в контексте расширения, права, обмен сообщениями и работа с конфиденциальными данными.",
    ),
    "cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html": (
        CAT_DEV,
        "Ужесточение сборки нативного кода на C/C++: флаги компилятора, защиты линкера и снижение эксплуатируемости бинарников.",
    ),
    "cheatsheets/CI_CD_Security_Cheat_Sheet.html": (
        CAT_DEV,
        "Защита конвейеров непрерывной интеграции и доставки: секреты, доверие к агентам, подпись артефактов и контроль пайплайна.",
    ),
    "cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html": (
        CAT_AUTH,
        "Риски секретных вопросов для восстановления доступа и альтернативы. Как снизить угрозу угадывания и сбора данных злоумышленником.",
    ),
    "cheatsheets/Clickjacking_Defense_Cheat_Sheet.html": (
        CAT_WEB,
        "Защита интерфейса от принудительных кликов через iframe и наложение: X-Frame-Options, CSP frame-ancestors и смежные меры.",
    ),
    "cheatsheets/Content_Security_Policy_Cheat_Sheet.html": (
        CAT_WEB,
        "Настройка Content Security Policy для ограничения источников скриптов и ресурсов и снижения эффективности XSS и инъекций контента.",
    ),
    "cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html": (
        CAT_MOD,
        "Меры против кражи сеансовых cookie и их повторного использования: флаги, привязка к каналу, SameSite и мониторинг аномалий.",
    ),
    "cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html": (
        CAT_MOD,
        "Защита от атак с подбором утёкших пар (credential stuffing): ограничение частоты, MFA, сигналы компрометации и политики паролей.",
    ),
    "cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение CSRF в веб-приложениях: синхронизатор токенов, SameSite, проверка заголовков и безопасные паттерны для API.",
    ),
    "cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Снижение риска межсайтового скриптинга: экранирование, контекст вывода, CSP и безопасная работа с HTML и пользовательским вводом.",
    ),
    "cheatsheets/Cryptographic_Storage_Cheat_Sheet.html": (
        CAT_PLAT,
        "Выбор алгоритмов, режимов и ключей для хранения чувствительных данных. Избегание слабых конструкций и типовых криптографических ошибок.",
    ),
    "cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html": (
        CAT_MOD,
        "Предотвращение DOM clobbering в клиентском коде: конфликты имён глобальных переменных с разметкой и меры на уровне шаблонов и скриптов.",
    ),
    "cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Защита от XSS, возникающего при обработке данных в браузере без отдельного ответа сервера с полезной нагрузкой (источники и безопасные API).",
    ),
    "cheatsheets/Database_Security_Cheat_Sheet.html": (
        CAT_CLOUD,
        "Безопасность СУБД: учётки, сеть, шифрование, минимальные привилегии и защита от несанкционированного доступа к данным.",
    ),
    "cheatsheets/Denial_of_Service_Cheat_Sheet.html": (
        CAT_WEB,
        "Противодействие отказу в обслуживании: лимиты, кэширование, масштабирование и выявление злоупотреблений на уровне приложения.",
    ),
    "cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html": (
        CAT_DEV,
        "Построение графа зависимостей и SBOM для прозрачности поставки и реагирования на уязвимости в сторонних компонентах.",
    ),
    "cheatsheets/Deserialization_Cheat_Sheet.html": (
        CAT_WEB,
        "Безопасная десериализация: риски выполнения кода и обхода логики, допустимые форматы и изоляция недоверенных данных.",
    ),
    "cheatsheets/Django_REST_Framework_Cheat_Sheet.html": (
        CAT_FW,
        "Практики ИБ при использовании Django REST Framework: аутентификация, права, сериализация и типовые ошибки конфигурации API.",
    ),
    "cheatsheets/Django_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Настройки и паттерны безопасности приложений на Django: CSRF, сессии, заголовки и защита от распространённых веб-уязвимостей.",
    ),
    "cheatsheets/Docker_Security_Cheat_Sheet.html": (
        CAT_CLOUD,
        "Жёсткая конфигурация контейнеров Docker: образы, пользователь процесса, возможности ядра и сетевая изоляция.",
    ),
    "cheatsheets/DotNet_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Обзор механизмов безопасности платформы .NET и типовых рекомендаций для приложений на ASP.NET и связанном стеке.",
    ),
    "cheatsheets/Drone_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "Угрозы для БПЛА и наземной инфраструктуры: каналы управления, прошивки и физический периметр.",
    ),
    "cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html": (
        CAT_GEN,
        "Корректная проверка адресов электронной почты без лишнего раскрытия информации и с учётом злоупотреблений (спам, перечисление).",
    ),
    "cheatsheets/Error_Handling_Cheat_Sheet.html": (
        CAT_DEV,
        "Обработка ошибок без утечки внутренних деталей и стеков. Единообразные ответы и безопасное журналирование инцидентов.",
    ),
    "cheatsheets/File_Upload_Cheat_Sheet.html": (
        CAT_WEB,
        "Безопасная загрузка файлов: проверка типа и содержимого, изоляция хранения, запрет опасных расширений и исполнения в контексте веб-сервера.",
    ),
    "cheatsheets/Forgot_Password_Cheat_Sheet.html": (
        CAT_AUTH,
        "Безопасный сценарий восстановления пароля: токены, срок жизни, защита от перечисления учётных записей и злоупотребления почтой.",
    ),
    "cheatsheets/GraphQL_Cheat_Sheet.html": (
        CAT_FW,
        "ИБ GraphQL API: ограничение глубины и сложности запросов, авторизация на уровне полей и защита от чрезмерной выдачи данных.",
    ),
    "cheatsheets/HTML5_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "Риски и настройки, связанные с API и разметкой HTML5: хранилища, CORS, встроенный контент и смежные векторы в браузере.",
    ),
    "cheatsheets/HTTP_Headers_Cheat_Sheet.html": (
        CAT_WEB,
        "Набор заголовков HTTP для усиления безопасности браузера: CSP, HSTS, X-Content-Type-Options и другие директивы.",
    ),
    "cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html": (
        CAT_WEB,
        "Внедрение HSTS для принудительного HTTPS, снижения риска SSL stripping и ошибок смешанного контента.",
    ),
    "cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html": (
        CAT_DEV,
        "Безопасность описаний инфраструктуры как кода: секреты в репозиториях, политики, обзор изменений и минимизация привилегий.",
    ),
    "cheatsheets/Injection_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Общие принципы защиты от инъекций: параметризация, контекстные экранирование и недопущение интерпретации ввода как кода.",
    ),
    "cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение инъекций в приложениях на Java: JDBC, JPA, шаблоны запросов и работа с внешними интерпретаторами.",
    ),
    "cheatsheets/Input_Validation_Cheat_Sheet.html": (
        CAT_FW,
        "Валидация и нормализация входных данных на границе приложения: белые списки, типы, ограничения длины и кодировки.",
    ),
    "cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение IDOR: косвенные ссылки, проверка владения ресурсом на сервере и отказ от доверия клиентским идентификаторам.",
    ),
    "cheatsheets/JAAS_Cheat_Sheet.html": (
        CAT_AUTH,
        "Использование JAAS в Java для подключаемой аутентификации и авторизации с учётом типовых ошибок конфигурации LoginModule.",
    ),
    "cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html": (
        CAT_FW,
        "Безопасная работа с JWT в Java: подпись, алгоритмы, хранение и проверка claims, сроки жизни и отзыв сеансов.",
    ),
    "cheatsheets/Java_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Свод рекомендаций по безопасности приложений на Java: classpath, десериализация, SecurityManager и криптография.",
    ),
    "cheatsheets/Key_Management_Cheat_Sheet.html": (
        CAT_PLAT,
        "Жизненный цикл криптографических ключей: генерация, хранение, ротация и разграничение доступа к материалам ключей.",
    ),
    "cheatsheets/Kubernetes_Security_Cheat_Sheet.html": (
        CAT_CLOUD,
        "Безопасность кластеров Kubernetes: RBAC, сетевые политики, образы и изоляция рабочих нагрузок.",
    ),
    "cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение LDAP-инъекций при построении фильтров и DN: параметризация, экранирование и отказ от конкатенации ввода.",
    ),
    "cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html": (
        CAT_MOD,
        "Защита приложений с LLM от prompt injection: разделение инструкций и данных, политики вывода и контроль инструментов.",
    ),
    "cheatsheets/Laravel_Cheat_Sheet.html": (
        CAT_FW,
        "Практики безопасности веб-приложений на Laravel: конфигурация, ORM, CSRF, массовое присвоение и заголовки.",
    ),
    "cheatsheets/Legacy_Application_Management_Cheat_Sheet.html": (
        CAT_GEN,
        "Сопровождение унаследованных систем: ограничение поверхности атаки, компенсирующие контроли и безопасные процессы изменений.",
    ),
    "cheatsheets/Logging_Cheat_Sheet.html": (
        CAT_DEV,
        "Что и как журналировать для расследований без избыточного хранения персональных и секретных данных.",
    ),
    "cheatsheets/Logging_Vocabulary_Cheat_Sheet.html": (
        CAT_DEV,
        "Согласованная терминология и поля событий безопасности для корреляции и обмена между системами и командами.",
    ),
    "cheatsheets/MCP_Security_Cheat_Sheet.html": (
        CAT_GEN,
        "Угрозы и меры для Model Context Protocol: доверие к инструментам, границы контекста и защита от злоупотребления агентами.",
    ),
    "cheatsheets/Mass_Assignment_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение массового присвоения полей модели: явные списки разрешённых атрибутов и разделение DTO.",
    ),
    "cheatsheets/Microservices_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "ИБ распределённых систем из микросервисов: аутентификация сервис-сервис, mTLS, секреты и границы доверия.",
    ),
    "cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.html": (
        CAT_PLAT,
        "Документирование архитектуры безопасности микросервисов: потоки доверия, границы и требования для аудита и онбординга.",
    ),
    "cheatsheets/Mobile_Application_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "Типовые риски мобильных приложений: хранилище, транспорт, обфускация и взаимодействие с бэкендом.",
    ),
    "cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html": (
        CAT_PLAT,
        "Изоляция данных и полномочий в мультитенантных приложениях: схемы разделения и проверки на каждом запросе.",
    ),
    "cheatsheets/Multifactor_Authentication_Cheat_Sheet.html": (
        CAT_AUTH,
        "Внедрение многофакторной аутентификации: факторы, резервные коды, UX и устойчивость к обходу и фишингу.",
    ),
    "cheatsheets/NPM_Security_Cheat_Sheet.html": (
        CAT_GEN,
        "Безопасность проектов на Node.js с экосистемой npm: зависимости, скрипты установки и целостность пакетов.",
    ),
    "cheatsheets/Network_Segmentation_Cheat_Sheet.html": (
        CAT_CLOUD,
        "Сегментация сети для ограничения перемещения злоумышленника: зоны, фильтрация и минимизация доверенных путей.",
    ),
    "cheatsheets/NoSQL_Security_Cheat_Sheet.html": (
        CAT_CLOUD,
        "Безопасность NoSQL-хранилищ: инъекции в запросах, права доступа и шифрование данных at rest и in transit.",
    ),
    "cheatsheets/NodeJS_Docker_Cheat_Sheet.html": (
        CAT_FW,
        "Совместное применение рекомендаций по Node.js и контейнеризации Docker для снижения рисков в типовых стеках.",
    ),
    "cheatsheets/Nodejs_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Безопасность серверных приложений на Node.js: зависимости, асинхронные ошибки, заголовки и работа с секретами.",
    ),
    "cheatsheets/OAuth2_Cheat_Sheet.html": (
        CAT_FW,
        "Корректное использование OAuth 2.0: потоки, redirect URI, хранение токенов и защита от утечек и подмены.",
    ),
    "cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html": (
        CAT_WEB,
        "Защита от инъекций команд ОС: избегание shell, списки разрешённых аргументов и изоляция вызовов внешних программ.",
    ),
    "cheatsheets/PHP_Configuration_Cheat_Sheet.html": (
        CAT_GEN,
        "Параметры php.ini и среды выполнения PHP, снижающие риск утечек, включения файлов и небезопасных функций.",
    ),
    "cheatsheets/Password_Storage_Cheat_Sheet.html": (
        CAT_AUTH,
        "Хранение паролей с современными алгоритмами хеширования (например, bcrypt, Argon2), солью и защитой от перебора.",
    ),
    "cheatsheets/Pinning_Cheat_Sheet.html": (
        CAT_PLAT,
        "Закрепление открытых ключей или сертификатов (pinning) в клиентах для снижения риска атак на доверие к PKI.",
    ),
    "cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение prototype pollution в JavaScript: безопасное слияние объектов, freeze и ограничение недоверенных структур.",
    ),
    "cheatsheets/Query_Parameterization_Cheat_Sheet.html": (
        CAT_FW,
        "Параметризованные запросы к БМД как основной контроль против SQL-инъекций и смежных векторов в запросах.",
    ),
    "cheatsheets/REST_Assessment_Cheat_Sheet.html": (
        CAT_FW,
        "Подходы к оценке и тестированию безопасности REST API: аутентификация, объекты, ошибки и типовые антипаттерны.",
    ),
    "cheatsheets/REST_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Проектирование и эксплуатация защищённых REST-сервисов: версии, методы, кэш и согласованная модель доступа.",
    ),
    "cheatsheets/Ruby_on_Rails_Cheat_Sheet.html": (
        CAT_FW,
        "Рекомендации по безопасности приложений Ruby on Rails: strong parameters, CSRF, XSS и настройки по умолчанию.",
    ),
    "cheatsheets/SAML_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Безопасная интеграция SAML SSO: подпись и шифрование утверждений, метаданные и защита от подмены и replay.",
    ),
    "cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение SQL-инъекций через подготовленные выражения, ORM и запрет динамической сборки запросов из сырого ввода.",
    ),
    "cheatsheets/Secrets_Management_Cheat_Sheet.html": (
        CAT_PLAT,
        "Управление секретами приложений и инфраструктуры: хранилища, ротация, доступ по ролям и исключение утечек в репозитории.",
    ),
    "cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html": (
        CAT_MOD,
        "Безопасность конвейеров ИИ: целостность данных и моделей, доступ к артефактам и контроль развёртывания.",
    ),
    "cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html": (
        CAT_CLOUD,
        "Принципы проектирования защищённых облачных решений: идентичность, сеть, шифрование и разделение сред.",
    ),
    "cheatsheets/Secure_Code_Review_Cheat_Sheet.html": (
        CAT_DEV,
        "Чек-листы и фокусы при ручном анализе кода на уязвимости: приоритетные категории дефектов и типовые места ошибок.",
    ),
    "cheatsheets/Secure_Product_Design_Cheat_Sheet.html": (
        CAT_DEV,
        "Встраивание требований безопасности на этапе проектирования продукта: угрозы, приватность и минимизация данных.",
    ),
    "cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.html": (
        CAT_PLAT,
        "Риски, связанные с CSS (утечки через стили, влияние на UI), и меры для снижения побочных эффектов в веб-приложениях.",
    ),
    "cheatsheets/Security_Terminology_Cheat_Sheet.html": (
        CAT_GEN,
        "Согласованные определения терминов ИБ для единого языка в командах разработки, эксплуатации и безопасности.",
    ),
    "cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Предотвращение SSRF: блоклисты и аллоулисты целевых хостов, разделение сетей и контроль исходящих запросов сервера.",
    ),
    "cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html": (
        CAT_CLOUD,
        "ИБ бессерверных и FaaS-развёртываний: IAM, события, холодный старт секретов и минимизация прав функций.",
    ),
    "cheatsheets/Session_Management_Cheat_Sheet.html": (
        CAT_AUTH,
        "Управление сеансами: идентификаторы, инвалидация, привязка к клиенту и защита от фиксации и кражи сеанса.",
    ),
    "cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html": (
        CAT_DEV,
        "Защита цепочки поставки ПО: проверка происхождения артефактов, подписи, зависимости и доверие к инструментам сборки.",
    ),
    "cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html": (
        CAT_MOD,
        "Предотвращение захвата поддоменов из-за висячих DNS-записей и освобождённых облачных ресурсов.",
    ),
    "cheatsheets/Symfony_Cheat_Sheet.html": (
        CAT_FW,
        "Рекомендации по безопасности приложений на Symfony: формы, безопасный компонент, конфигурация и типовые ловушки.",
    ),
    "cheatsheets/TLS_Cipher_String_Cheat_Sheet.html": (
        CAT_WEB,
        "Подбор и сопровождение наборов шифров TLS для баланса совместимости и криптостойкости на серверах и прокси.",
    ),
    "cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html": (
        CAT_MOD,
        "Контроль стороннего JavaScript: SRI, CSP, поставщики тегов и снижение риска компрометации цепочки загрузки скриптов.",
    ),
    "cheatsheets/Third_Party_Payment_Gateway_Integration_Cheat_Sheet.html": (
        CAT_GEN,
        "Безопасная интеграция платёжных шлюзов: PCI DSS, токенизация, вебхуки и защита от подмены платёжных callback.",
    ),
    "cheatsheets/Threat_Modeling_Cheat_Sheet.html": (
        CAT_PLAT,
        "Практическое моделирование угроз: границы системы, активы, злоумышленники и приоритизация контролей.",
    ),
    "cheatsheets/Transaction_Authorization_Cheat_Sheet.html": (
        CAT_AUTH,
        "Авторизация чувствительных транзакций (платежи, изменение критичных данных) поверх обычной сессии пользователя.",
    ),
    "cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html": (
        CAT_WEB,
        "Защита данных при передаче: TLS end-to-end, проверка сертификатов и типичные ошибки конфигурации канала.",
    ),
    "cheatsheets/Transport_Layer_Security_Cheat_Sheet.html": (
        CAT_WEB,
        "Обзор и практика использования TLS: версии протокола, сертификаты, Perfect Forward Secrecy и отключение слабых алгоритмов.",
    ),
    "cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html": (
        CAT_WEB,
        "Исключение открытых перенаправлений и внутренних форвардов, приводящих к фишингу и обходу проверок доступа.",
    ),
    "cheatsheets/User_Privacy_Protection_Cheat_Sheet.html": (
        CAT_GEN,
        "Минимизация и защита персональных данных пользователей: согласия, хранение, удаление и прозрачность обработки.",
    ),
    "cheatsheets/Virtual_Patching_Cheat_Sheet.html": (
        CAT_DEV,
        "Временная компенсация уязвимостей на периметре или в WAF без немедленного патча кода приложения.",
    ),
    "cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html": (
        CAT_DEV,
        "Процессы координированного раскрытия уязвимостей: каналы связи, сроки, безопасный обмен информацией с исследователями.",
    ),
    "cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html": (
        CAT_DEV,
        "Выявление и устранение уязвимых зависимостей: сканирование, политики обновлений и приоритизация по эксплуатации.",
    ),
    "cheatsheets/WebSocket_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Безопасность WebSocket: аутентификация после upgrade, авторизация сообщений и защита от CSRF при установке соединения.",
    ),
    "cheatsheets/Web_Service_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Общие меры для SOAP и XML-веб-сервисов: подпись, шифрование сообщений и защита от перегрузки и инъекций в XML.",
    ),
    "cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html": (
        CAT_WEB,
        "Отключение и ограничение внешних сущностей в XML-парсерах для предотвращения XXE и утечек файлов.",
    ),
    "cheatsheets/XML_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Комплексная безопасность XML: схемы, подпись, шифрование и защита от расширенных атак на парсеры и преобразования.",
    ),
    "cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html": (
        CAT_WEB,
        "Понимание приёмов обхода слабых XSS-фильтров для построения устойчивой защиты на экранировании и CSP, а не на чёрных списках.",
    ),
    "cheatsheets/XS_Leaks_Cheat_Sheet.html": (
        CAT_MOD,
        "Межсайтовые утечки состояния (XS-Leaks): побочные каналы в браузере и меры изоляции между источниками.",
    ),
    "cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.html": (
        CAT_PLAT,
        "Принципы Zero Trust: верификация каждого запроса, микросегментация и отказ от неявного доверия внутри периметра.",
    ),
    "cheatsheets/gRPC_Security_Cheat_Sheet.html": (
        CAT_FW,
        "Безопасность gRPC: TLS, аутентификация вызовов, метаданные и политики на уровне сервисов.",
    ),
}


def load_glossary_items():
    text = GLOSSARY_PATH.read_text(encoding="utf-8")
    pat = re.compile(
        r'<a href="(cheatsheets/[^"]+)"[^>]*class="md-nav__link">'
        r"[\s\S]*?"
        r'<span class="md-ellipsis">\s*\n\s*([^<\n]+?)\s*\n',
        re.MULTILINE,
    )
    return pat.findall(text)


def main():
    rows = load_glossary_items()
    missing_meta = [u for u, _ in rows if u not in META]
    if missing_meta:
        raise SystemExit(f"Нет META для URL: {missing_meta}")
    extra = set(META) - {u for u, _ in rows}
    if extra:
        raise SystemExit(f"Лишние ключи META (нет в глоссарии): {sorted(extra)}")

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cheatsheets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            short_description TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE
        )
        """
    )
    cur.execute("SELECT url FROM cheatsheets")
    before = {r[0] for r in cur.fetchall()}

    added = 0
    updated = 0
    for url, title in rows:
        title = title.strip()
        category, short_description = META[url]
        if url in before:
            updated += 1
        else:
            added += 1
        cur.execute(
            """
            INSERT INTO cheatsheets (title, category, short_description, url)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                title = excluded.title,
                category = excluded.category,
                short_description = excluded.short_description
            """,
            (title, category, short_description, url),
        )

    con.commit()
    con.close()
    print(f"Добавлено новых записей: {added}. Обновлено существующих: {updated}.")


if __name__ == "__main__":
    main()
