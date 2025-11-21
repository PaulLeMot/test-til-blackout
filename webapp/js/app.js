class SecurityDashboard {
    constructor() {
        this.apiEndpoints = [];
        this.currentGraph = null;
        this.currentData = [];
        this.filteredData = [];
        this.currentPage = 1;
        this.pageSize = 20;
        this.filters = {
            severity: '',
            category: '',
            bank: ''
        };
        this.isScanning = false;
        this.lastDataCount = 0;
        this.sessions = [];
        this.activeSection = 'dashboard'; // 'dashboard', 'comparison', 'apiGraph'
        this.scanStatusCheckInterval = null; // ДОБАВЛЕНО: Интервал для проверки статуса
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupConfigListeners();
        this.setupBankCards();
        this.setupModeSelector();
        this.connectWebSocket();
        this.loadInitialData();
        this.restoreState();
        this.setupLogoClick();
        this.startScanStatusPolling();
        this.loadLocalSpecificationsList(); // ДОБАВЛЕНО: Загрузка списка локальных спецификаций
    }

    // ДОБАВЛЕНО: Загрузка списка локальных спецификаций
    async loadLocalSpecificationsList() {
        try {
            const response = await fetch('/api/specs/local');
            if (response.ok) {
                const specs = await response.json();
                this.populateLocalSpecSelect(specs);
            }
        } catch (error) {
            console.error('Error loading local specifications:', error);
        }
    }

    // ДОБАВЛЕНО: Заполнение выпадающего списка локальных спецификаций
    populateLocalSpecSelect(specs) {
        const select = document.getElementById('localSpecSelect');
        if (!select) return;

        // Очищаем существующие опции (кроме первой)
        while (select.children.length > 1) select.removeChild(select.lastChild);

        specs.forEach(spec => {
            const option = document.createElement('option');
            option.value = spec.filename;
            option.textContent = `${spec.filename} (${spec.size} bytes)`;
            select.appendChild(option);
        });
    }

    setupModeSelector() {
        const modeRadios = document.querySelectorAll('input[name="analysisMode"]');
        const modeInfo = document.getElementById('modeInfo');

        modeRadios.forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.handleModeChange(e.target.value);
            });
        });

        // Инициализируем начальное состояние
        this.handleModeChange('DYNAMIC_ONLY');
    }

    handleModeChange(selectedMode) {
        const modeInfo = document.getElementById('modeInfo');
        const bankCards = document.querySelectorAll('.bank-config');

        // Сбрасываем информационные сообщения
        modeInfo.innerHTML = '';
        modeInfo.style.display = 'block';

        // Показываем/скрываем элементы в зависимости от режима
        switch(selectedMode) {
            case 'STATIC_ONLY':
                // Скрываем поля URL банков
                bankCards.forEach(card => {
                    card.querySelector('.bank-url').closest('.input-group').style.display = 'none';
                    card.querySelector('.bank-spec').closest('.input-group').style.display = 'none';
                });
                modeInfo.innerHTML = '<div class="info-message">📁 Будут проанализированы спецификации из папки Specifications</div>';
                modeInfo.className = 'mode-info info-static';
                break;

            case 'COMBINED':
                // Показываем только URL цели, скрываем URL спецификации
                bankCards.forEach(card => {
                    card.querySelector('.bank-url').closest('.input-group').style.display = 'block';
                    card.querySelector('.bank-spec').closest('.input-group').style.display = 'none';
                });
                modeInfo.innerHTML = '<div class="info-message">🔗 Будут проанализированы локальные спецификации с отправкой запросов на указанный URL</div>';
                modeInfo.className = 'mode-info info-combined';
                break;

            case 'DYNAMIC_ONLY':
            default:
                // Показываем все поля
                bankCards.forEach(card => {
                    card.querySelector('.bank-url').closest('.input-group').style.display = 'block';
                    card.querySelector('.bank-spec').closest('.input-group').style.display = 'block';
                });
                modeInfo.innerHTML = '<div class="info-message">🌐 Спецификация загружается по URL, запросы отправляются на целевой URL</div>';
                modeInfo.className = 'mode-info info-dynamic';
                break;
        }
    }

    startScanStatusPolling() {
        // Проверяем статус каждые 3 секунды
        this.scanStatusCheckInterval = setInterval(() => {
            this.checkScanStatus();
        }, 3000);
    }

    // ДОБАВЛЕНО: Метод для проверки статуса сканирования
    async checkScanStatus() {
        try {
            const response = await fetch('/api/scan/status');
            if (response.ok) {
                const status = await response.json();

                // Обновляем статус только если он изменился
                if (this.isScanning !== status.scanning) {
                    this.isScanning = status.scanning;
                    this.updateScanButton(this.isScanning);

                    // Показываем уведомление при завершении сканирования
                    if (!this.isScanning && this.wasScanning) {
                        this.showNotification('Сканирование завершено', 'success');
                    }

                    this.wasScanning = this.isScanning;
                }
            }
        } catch (error) {
            console.error('Error checking scan status:', error);
        }
    }

    setupLogoClick() {
        const logo = document.querySelector('.app-title');
        if (logo) {
            logo.style.cursor = 'pointer';
            logo.addEventListener('click', () => {
                this.showMainDashboard();
            });
        }
    }

    setupEventListeners() {
        document.getElementById('startScanBtn').addEventListener('click', () => {
            this.startScan();
        });

        document.getElementById('applyFilters').addEventListener('click', () => {
            this.applyFilters();
        });

        document.getElementById('clearFilters').addEventListener('click', () => {
            this.clearFilters();
        });

        document.getElementById('prevPage').addEventListener('click', () => {
            this.previousPage();
        });

        document.getElementById('nextPage').addEventListener('click', () => {
            this.nextPage();
        });

        document.getElementById('exportCsv').addEventListener('click', () => {
            this.exportToCsv();
        });

        document.getElementById('exportPdf').addEventListener('click', () => {
            this.exportToPdf();
        });

        document.querySelector('.close').addEventListener('click', () => {
            this.closeModal();
        });

        window.addEventListener('click', (e) => {
            if (e.target === document.getElementById('vulnerabilityModal')) {
                this.closeModal();
            }
        });

        // Обновленные обработчики для кнопок переключения
        document.getElementById('showComparison').addEventListener('click', () => {
            this.toggleComparisonSection();
        });

        document.getElementById('showApiGraph').addEventListener('click', () => {
            this.toggleApiGraphSection();
        });

        document.getElementById('compareSessions').addEventListener('click', () => {
            this.compareSessions();
        });

        document.getElementById('closeComparison').addEventListener('click', () => {
            this.hideComparisonSection();
        });

        // Сохраняем состояние при закрытии страницы
        window.addEventListener('beforeunload', () => {
            this.saveState();
        });

        document.getElementById('loadGraph').addEventListener('click', () => {
            this.loadApiGraph();
        });

        document.getElementById('refreshGraph').addEventListener('click', () => {
            this.loadApiGraph();
        });

        document.getElementById('closePanel').addEventListener('click', () => {
            this.hideEndpointPanel();
        });

        document.getElementById('testForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.testEndpoint();
        });

        // ДОБАВЛЕНО: Обработчики для работы с файлами
        document.getElementById('loadGraphFromFile').addEventListener('click', () => {
            this.loadApiGraphFromFile();
        });

        document.getElementById('loadLocalSpec').addEventListener('click', () => {
            this.loadLocalSpecification();
        });

        document.getElementById('specFileInput').addEventListener('change', (e) => {
            this.handleFileSelect(e);
        });
    }

    // ДОБАВЛЕНО: Обработчик выбора файла
    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.showNotification(`Выбран файл: ${file.name}`, 'info');
        }
    }

    // ДОБАВЛЕНО: Загрузка графа из файла
    async loadApiGraphFromFile() {
        const fileInput = document.getElementById('specFileInput');
        const file = fileInput.files[0];

        if (!file) {
            this.showNotification('Выберите файл спецификации', 'error');
            return;
        }

        try {
            this.showNotification('Загрузка спецификации из файла...', 'info');

            const formData = new FormData();
            formData.append('specFile', file);

            const response = await fetch('/api/graph/upload', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const graphData = await response.json();
                this.renderApiGraph(graphData);
                this.showNotification(`Загружено ${graphData.totalEndpoints} эндпоинтов из файла`, 'success');
            } else {
                throw new Error('Failed to load graph from file');
            }
        } catch (error) {
            console.error('Error loading graph from file:', error);
            this.showNotification('Ошибка загрузки графа из файла', 'error');
        }
    }

    // ДОБАВЛЕНО: Загрузка локальной спецификации
    async loadLocalSpecification() {
        const select = document.getElementById('localSpecSelect');
        const filename = select.value;

        if (!filename) {
            this.showNotification('Выберите локальную спецификацию', 'error');
            return;
        }

        try {
            this.showNotification('Загрузка локальной спецификации...', 'info');

            const response = await fetch(`/api/graph/local?filename=${encodeURIComponent(filename)}`);
            if (response.ok) {
                const graphData = await response.json();
                this.renderApiGraph(graphData);
                this.showNotification(`Загружено ${graphData.totalEndpoints} эндпоинтов из ${filename}`, 'success');
            } else {
                throw new Error('Failed to load local specification');
            }
        } catch (error) {
            console.error('Error loading local specification:', error);
            this.showNotification('Ошибка загрузки локальной спецификации', 'error');
        }
    }

    setupConfigListeners() {
        document.getElementById('saveConfig').addEventListener('click', () => {
            this.saveConfiguration();
        });

        document.getElementById('loadDefaults').addEventListener('click', () => {
            this.loadDefaultConfiguration();
        });

        document.getElementById('clearDatabase').addEventListener('click', () => {
            this.clearDatabase();
        });

        // Загружаем сохраненные настройки при инициализации
        this.loadSavedConfiguration();
    }

    // Новый метод для показа главной панели
    showMainDashboard() {
        document.querySelector('.dashboard').style.display = 'block';
        document.getElementById('comparisonSection').style.display = 'none';
        document.getElementById('apiGraphSection').style.display = 'none';
        document.getElementById('configSection').style.display = 'block'; // Показываем настройки

        this.activeSection = 'dashboard';
        this.updateHeaderButtons();
    }

    // Обновленный метод для переключения секции сравнения
    toggleComparisonSection() {
        if (this.activeSection === 'comparison') {
            this.showMainDashboard();
        } else {
            document.querySelector('.dashboard').style.display = 'none';
            document.getElementById('comparisonSection').style.display = 'block';
            document.getElementById('apiGraphSection').style.display = 'none';
            document.getElementById('configSection').style.display = 'none'; // Скрываем настройки

            this.activeSection = 'comparison';
            this.updateHeaderButtons();

            // Загружаем список сессий при открытии
            this.loadSessionsList();
            this.showNotification('Выберите две сессии для сравнения', 'info');
        }
    }

    // Обновленный метод для переключения секции графа API
    toggleApiGraphSection() {
        if (this.activeSection === 'apiGraph') {
            this.showMainDashboard();
        } else {
            document.querySelector('.dashboard').style.display = 'none';
            document.getElementById('comparisonSection').style.display = 'none';
            document.getElementById('apiGraphSection').style.display = 'block';
            document.getElementById('configSection').style.display = 'none'; // Скрываем настройки

            this.activeSection = 'apiGraph';
            this.updateHeaderButtons();

            // Автоматически загружаем граф если есть URL
            const specUrl = document.getElementById('specUrlInput').value;
            if (specUrl) {
                setTimeout(() => this.loadApiGraph(), 500);
            }

            // Загружаем список локальных спецификаций
            this.loadLocalSpecificationsList();
        }
    }

    // Новый метод для обновления состояния кнопок в заголовке
    updateHeaderButtons() {
        const comparisonBtn = document.getElementById('showComparison');
        const apiGraphBtn = document.getElementById('showApiGraph');

        // Сбрасываем все кнопки к обычному состоянию
        comparisonBtn.classList.remove('btn-primary');
        comparisonBtn.classList.add('btn-secondary');
        apiGraphBtn.classList.remove('btn-primary');
        apiGraphBtn.classList.add('btn-secondary');

        // Подсвечиваем активную кнопку
        if (this.activeSection === 'comparison') {
            comparisonBtn.classList.remove('btn-secondary');
            comparisonBtn.classList.add('btn-primary');
        } else if (this.activeSection === 'apiGraph') {
            apiGraphBtn.classList.remove('btn-secondary');
            apiGraphBtn.classList.add('btn-primary');
        }
    }

    // Обновляем метод hideComparisonSection
    hideComparisonSection() {
        this.showMainDashboard();
    }

    // Добавляем метод hideApiGraphSection для кнопки закрытия в графе API
    hideApiGraphSection() {
        this.showMainDashboard();
    }

    async clearDatabase() {
        if (!confirm('Вы уверены, что хотите полностью очистить базу данных? Это действие нельзя отменить.')) {
            return;
        }

        try {
            this.showNotification('Очистка базы данных...', 'info');

            const response = await fetch('/api/scan/clear', {
                method: 'POST'
            });

            if (response.ok) {
                this.showNotification('База данных успешно очищена', 'success');
                // Обновляем данные на странице
                this.currentData = [];
                this.filteredData = [];
                this.currentPage = 1;
                this.renderTable();
                this.updateStats();
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            console.error('Error clearing database:', error);
            this.showNotification('Ошибка при очистке базы данных', 'error');
        }
    }

    saveConfiguration() {
    // Собираем данные банков из всех карточек
    const bankCards = document.querySelectorAll('.bank-config');
    const banks = [];

    bankCards.forEach(card => {
        const baseUrl = card.querySelector('.bank-url').value.trim();
        const specUrl = card.querySelector('.bank-spec').value.trim();

        if (baseUrl || specUrl) { // Добавляем только если есть данные
            banks.push({
                baseUrl: baseUrl,
                specUrl: specUrl
            });
        }
    });

    const config = {
        bankId: document.getElementById('bankId').value.trim(),
        banks: banks,
        credentials: [
            {
                username: document.getElementById('user1').value.trim(),
                password: document.getElementById('password1').value
            },
            {
                username: document.getElementById('user2').value.trim(),
                password: document.getElementById('password2').value
            }
        ]
    };

    if (!this.validateConfiguration(config)) {
        return;
    }

    localStorage.setItem('scanConfig', JSON.stringify(config));
    this.showNotification('Настройки сохранены', 'success');
}

    loadSavedConfiguration() {
        try {
            const saved = localStorage.getItem('scanConfig');
            if (saved) {
                const config = JSON.parse(saved);
                this.applyConfiguration(config);
            }
        } catch (e) {
            console.warn('Failed to load saved configuration:', e);
        }
    }

    loadDefaultConfiguration() {
    const defaultConfig = {
        bankId: "team172",
        banks: [
            {
                baseUrl: "",
                specUrl: ""
            }
        ],
        credentials: [
            {
                username: "",
                password: ""
            },
            {
                username: "",
                password: ""
            }
        ]
    };

    this.applyConfiguration(defaultConfig);
    this.showNotification('Настройки по умолчанию загружены', 'info');
}

    applyConfiguration(config) {
    // Устанавливаем bankId
    document.getElementById('bankId').value = config.bankId || 'team172';

    // ДОБАВЛЕНО: устанавливаем API credentials
    document.getElementById('clientId').value = config.clientId || 'team172';
    document.getElementById('clientSecret').value = config.clientSecret || '';

    // Очищаем и пересоздаем карточки банков
    const container = document.getElementById('bankCardsContainer');
    container.innerHTML = '';

    // Создаем карточки для каждого банка из конфигурации
    config.banks.forEach(bank => {
        this.addBankCard(bank);
    });

    // Если нет банков в конфиге, создаем одну пустую карточку
    if (config.banks.length === 0) {
        this.addBankCard();
    }

    // Учетные данные
    config.credentials.forEach((cred, index) => {
        document.getElementById(`user${index + 1}`).value = cred.username;
        document.getElementById(`password${index + 1}`).value = cred.password;
    });

    // Устанавливаем режим анализа
    if (config.analysisMode) {
        document.querySelector(`input[name="analysisMode"][value="${config.analysisMode}"]`).checked = true;
        this.handleModeChange(config.analysisMode);
    }
}

    validateConfiguration(config) {
        // Проверяем bankId
        if (!config.bankId || config.bankId.trim() === '') {
            this.showNotification('Введите Bank ID (Team ID)', 'error');
            return false;
        }

        // Проверяем URL банков
        for (let bank of config.banks) {
            if (!bank.baseUrl || !bank.specUrl) {
                this.showNotification('Заполните все URL банков', 'error');
                return false;
            }

            try {
                new URL(bank.baseUrl);
                new URL(bank.specUrl);
            } catch (e) {
                this.showNotification('Некорректный URL', 'error');
                return false;
            }
        }

        // Проверяем учетные данные
        for (let cred of config.credentials) {
            if (!cred.username || !cred.password) {
                this.showNotification('Заполните все учетные данные', 'error');
                return false;
            }
        }

        return true;
    }

    getCurrentConfiguration() {
    try {
        const bankCards = document.querySelectorAll('.bank-config');
        const banks = [];

        bankCards.forEach(card => {
            const baseUrl = card.querySelector('.bank-url').value.trim();
            const specUrl = card.querySelector('.bank-spec').value.trim();

            if (baseUrl || specUrl) {
                banks.push({
                    baseUrl: baseUrl,
                    specUrl: specUrl
                });
            }
        });

        const selectedMode = document.querySelector('input[name="analysisMode"]:checked').value;

        const config = {
            bankId: document.getElementById('bankId').value.trim(),
            banks: banks,
            credentials: [
                {
                    username: document.getElementById('user1').value.trim(),
                    password: document.getElementById('password1').value
                },
                {
                    username: document.getElementById('user2').value.trim(),
                    password: document.getElementById('password2').value
                }
            ],
            analysisMode: selectedMode,
            // ДОБАВЛЕНО: credentials для API
            clientId: document.getElementById('clientId').value.trim(),
            clientSecret: document.getElementById('clientSecret').value
        };

        return config;
    } catch (e) {
        console.error('Error getting configuration:', e);
        return null;
    }
}

    connectWebSocket() {
        // Используем HTTP polling вместо WebSocket (для простоты)
        this.startPolling();
    }

    startPolling() {
        // Опрашиваем сервер каждые 2 секунды
        setInterval(() => {
            this.loadInitialData();
        }, 2000);
    }

    // Метод для сохранения состояния
    saveState() {
        const state = {
            filters: this.filters,
            currentPage: this.currentPage,
            pageSize: this.pageSize
        };
        localStorage.setItem('dashboardState', JSON.stringify(state));
    }

    // Метод для восстановления состояния
    restoreState() {
        try {
            const saved = localStorage.getItem('dashboardState');
            if (saved) {
                const state = JSON.parse(saved);
                this.filters = state.filters || this.filters;
                this.currentPage = state.currentPage || this.currentPage;
                this.pageSize = state.pageSize || this.pageSize;

                // Восстанавливаем значения в полях фильтров
                if (this.filters.severity) {
                    document.getElementById('severityFilter').value = this.filters.severity;
                }
                if (this.filters.category) {
                    document.getElementById('categoryFilter').value = this.filters.category;
                }
                if (this.filters.bank) {
                    document.getElementById('bankFilter').value = this.filters.bank;
                }
            }
        } catch (e) {
            console.warn('Failed to restore state:', e);
        }
    }

    async loadInitialData() {
        try {
            const response = await fetch('/api/scan/results');
            if (response.ok) {
                const newData = await response.json();

                // Сохраняем текущее состояние перед обновлением
                const previousFilteredCount = this.filteredData.length;
                const hadData = this.currentData.length > 0;

                this.currentData = newData;

                // Если были применены фильтры, применяем их к новым данным
                if (this.filters.severity || this.filters.category || this.filters.bank) {
                    this.applyFilters(true); // true - не сбрасывать пагинацию
                } else {
                    this.filteredData = [...this.currentData];
                }

                // Обновляем интерфейс
                this.renderTable();
                this.updateStats();
                this.populateFilters();

                // Сохраняем состояние после обновления
                this.saveState();

                // Показываем уведомление о новых данных, если сканирование активно
                if (this.isScanning && newData.length > this.lastDataCount && hadData) {
                    const newCount = newData.length - this.lastDataCount;
                    this.showNotification(`Обнаружено ${newCount} новых уязвимостей`, 'info');
                }

                this.lastDataCount = newData.length;
            }
        } catch (error) {
            console.error('Error loading data:', error);
        }
    }

    async startScan() {
        if (this.isScanning) {
            this.showNotification('Сканирование уже выполняется', 'warning');
            return;
        }

        const config = this.getCurrentConfiguration();
        if (!config) {
            this.showNotification('Сначала сохраните настройки сканирования', 'error');
            return;
        }

        try {
            // Устанавливаем локальный статус сканирования
            this.isScanning = true;
            this.updateScanButton(true);
            this.showNotification('Запущено расширенное сканирование с новыми типами атак', 'success');
            this.lastDataCount = this.currentData.length;

            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });

            if (!response.ok) {
                throw new Error('Server error');
            }

            this.showNotification('Сканирование запущено. Ожидайте первые результаты...', 'info');

        } catch (error) {
            console.error('Error starting scan:', error);
            this.showNotification('Ошибка запуска сканирования', 'error');
            // Сбрасываем статус при ошибке
            this.isScanning = false;
            this.updateScanButton(false);
        }
    }

    updateScanButton(scanning) {
        const btn = document.getElementById('startScanBtn');
        if (scanning) {
            btn.innerHTML = '<span class="scanning-indicator"><span class="pulse">⏳</span> Расширенное сканирование...</span>';
            btn.disabled = true;
            btn.classList.add('scanning');
        } else {
            btn.innerHTML = 'Запустить расширенное сканирование';
            btn.disabled = false;
            btn.classList.remove('scanning');
        }
        this.updateConnectionStatus();
    }

    updateConnectionStatus() {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            if (this.isScanning) {
                statusElement.className = 'status-connecting';
                statusElement.textContent = 'Расширенное сканирование...';
            } else {
                statusElement.className = 'status-online';
                statusElement.textContent = 'Online';
            }
        }
    }

    updateStats() {
        const stats = {
            total: this.currentData.length,
            critical: this.currentData.filter(item => item.severity === 'CRITICAL').length,
            high: this.currentData.filter(item => item.severity === 'HIGH').length,
            medium: this.currentData.filter(item => item.severity === 'MEDIUM').length,
            low: this.currentData.filter(item => item.severity === 'LOW').length,
            byCategory: this.getCategoryStats(),
            byBank: this.getBankStats()
        };

        this.updateStatsDisplay(stats);
        this.updateCharts(stats);
    }

    getCategoryStats() {
        const categories = {};
        this.currentData.forEach(item => {
            categories[item.category] = (categories[item.category] || 0) + 1;
        });
        return categories;
    }

    getBankStats() {
        const banks = {};
        this.currentData.forEach(item => {
            banks[item.bankName] = (banks[item.bankName] || 0) + 1;
        });
        return banks;
    }

    updateStatsDisplay(stats) {
        if (document.getElementById('totalVulns')) {
            document.getElementById('totalVulns').textContent = stats.total;
        }
        if (document.getElementById('criticalCount')) {
            document.getElementById('criticalCount').textContent = stats.critical;
        }
        if (document.getElementById('highCount')) {
            document.getElementById('highCount').textContent = stats.high;
        }
        if (document.getElementById('mediumCount')) {
            document.getElementById('mediumCount').textContent = stats.medium;
        }
        if (document.getElementById('lowCount')) {
            document.getElementById('lowCount').textContent = stats.low;
        }
    }

    updateCharts(stats) {
        this.updateSeverityChart(stats);
        this.updateCategoryChart(stats.byCategory);
    }

    updateSeverityChart(stats) {
        const chart = document.getElementById('severityChart');
        if (!chart) return;

        const total = stats.total || 1;
        const data = [
            { label: 'Критические', value: stats.critical, color: '#ef4444', percent: (stats.critical / total * 100) },
            { label: 'Высокие', value: stats.high, color: '#f59e0b', percent: (stats.high / total * 100) },
            { label: 'Средние', value: stats.medium, color: '#eab308', percent: (stats.medium / total * 100) },
            { label: 'Низкие', value: stats.low, color: '#10b981', percent: (stats.low / total * 100) }
        ].filter(item => item.value > 0);

        if (data.length === 0) {
            chart.innerHTML = '<div class="chart-placeholder">Нет данных</div>';
            return;
        }

        const chartHtml = `
            <div class="simple-chart">
                ${data.map(item => `
                    <div class="chart-item">
                        <div class="chart-bar-container">
                            <div class="chart-bar" style="width: ${item.percent}%; background: ${item.color};"></div>
                        </div>
                        <div class="chart-label">
                            <span class="chart-color" style="background: ${item.color}"></span>
                            ${item.label}: ${item.value} (${item.percent.toFixed(1)}%)
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        chart.innerHTML = chartHtml;
    }

    updateCategoryChart(categoryData) {
        const chart = document.getElementById('categoryChart');
        if (!chart) return;

        const total = Object.values(categoryData).reduce((sum, val) => sum + val, 0) || 1;
        const data = Object.entries(categoryData)
            .map(([label, value]) => ({
                label: this.shortenCategoryName(label),
                value,
                percent: (value / total * 100)
            }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 12);

        if (data.length === 0) {
            chart.innerHTML = '<div class="chart-placeholder">Нет данных</div>';
            return;
        }

        const chartHtml = `
            <div class="simple-chart">
                ${data.map(item => `
                    <div class="chart-item">
                        <div class="chart-label" title="${item.label}">
                            ${item.label}
                        </div>
                        <div class="chart-bar-container">
                            <div class="chart-bar" style="width: ${item.percent}%; background: #3b82f6;"></div>
                            <span class="chart-value">${item.value}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        chart.innerHTML = chartHtml;
    }

    shortenCategoryName(name) {
        const shortNames = {
            'OWASP_API1_BOLA': 'API1 - BOLA',
            'OWASP_API2_BROKEN_AUTH': 'API2 - Broken Auth',
            'OWASP_API3_BOPLA': 'API3 - BOPLA',
            'OWASP_API4_URC': 'API4 - URC',
            'OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH': 'API5 - BFLA',
            'OWASP_API6_BUSINESS_FLOW': 'API6 - Business Flow',
            'OWASP_API7_SSRF': 'API7 - SSRF',
            'OWASP_API8_SM': 'API8 - Security Misconfig',
            'OWASP_API9_INVENTORY': 'API9 - Inventory',
            'OWASP_API10_UNSAFE_CONSUMPTION': 'API10 - Unsafe Consumption',
            'SQL_INJECTION': 'SQL Injection',
            'XSS': 'XSS',
            'PATH_TRAVERSAL': 'Path Traversal',
            'COMMAND_INJECTION': 'Command Injection',
            'NOSQL_INJECTION': 'NoSQL Injection',
            'BUSINESS_LOGIC_BYPASS': 'Business Logic Bypass',
            'SSTI': 'Server-Side Template Injection',
            'LDAP_INJECTION': 'LDAP Injection',
            'SSRF': 'SSRF'
        };
        return shortNames[name] || name.substring(0, 20) + (name.length > 20 ? '...' : '');
    }

    populateFilters() {
        const categoryFilter = document.getElementById('categoryFilter');
        const bankFilter = document.getElementById('bankFilter');

        if (!categoryFilter || !bankFilter) return;

        // Очищаем существующие опции
        while (categoryFilter.children.length > 1) categoryFilter.removeChild(categoryFilter.lastChild);
        while (bankFilter.children.length > 1) bankFilter.removeChild(bankFilter.lastChild);

        // Добавляем новые опции
        const categories = [...new Set(this.currentData.map(item => item.category))].sort();
        const banks = [...new Set(this.currentData.map(item => item.bankName))].sort();

        categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = this.shortenCategoryName(category);
            categoryFilter.appendChild(option);
        });

        banks.forEach(bank => {
            const option = document.createElement('option');
            option.value = bank;
            option.textContent = bank;
            bankFilter.appendChild(option);
        });

        // Восстанавливаем выбранные значения после обновления опций
        if (this.filters.category) {
            categoryFilter.value = this.filters.category;
        }
        if (this.filters.bank) {
            bankFilter.value = this.filters.bank;
        }
    }

    applyFilters(preservePagination = false) {
        const severity = document.getElementById('severityFilter').value;
        const category = document.getElementById('categoryFilter').value;
        const bank = document.getElementById('bankFilter').value;

        this.filters = {
            severity: severity || '',
            category: category || '',
            bank: bank || ''
        };

        this.filteredData = this.currentData.filter(item => {
            return (!this.filters.severity || item.severity === this.filters.severity) &&
                   (!this.filters.category || item.category === this.filters.category) &&
                   (!this.filters.bank || item.bankName === this.filters.bank);
        });

        if (!preservePagination) {
            this.currentPage = 1;
        }

        this.renderTable();
        this.saveState();
    }

    clearFilters() {
        document.getElementById('severityFilter').value = '';
        document.getElementById('categoryFilter').value = '';
        document.getElementById('bankFilter').value = '';
        this.filters = {
            severity: '',
            category: '',
            bank: ''
        };
        this.filteredData = [...this.currentData];
        this.currentPage = 1;
        this.renderTable();
        this.saveState();
    }

    renderTable() {
        const tbody = document.getElementById('resultsBody');
        if (!tbody) return;

        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = startIndex + this.pageSize;
        const pageData = this.filteredData.slice(startIndex, endIndex);

        tbody.innerHTML = '';

        if (pageData.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="no-data">Нет данных для отображения</td></tr>';
        } else {
            pageData.forEach(item => {
                const row = this.createTableRow(item);
                tbody.appendChild(row);
            });
        }

        this.updatePagination();
    }

    createTableRow(item) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${this.escapeHtml(item.bankName)}</td>
            <td class="vulnerability-title" title="${this.escapeHtml(item.vulnerabilityTitle)}">
                ${this.escapeHtml(item.vulnerabilityTitle)}
            </td>
            <td><span class="severity-badge severity-${item.severity.toLowerCase()}">${item.severity}</span></td>
            <td>${this.escapeHtml(this.shortenCategoryName(item.category))}</td>
            <td>${this.escapeHtml(item.statusCode || 'N/A')}</td>
            <td>${new Date(item.scanDate).toLocaleDateString('ru-RU')}</td>
            <td>
                <button class="btn btn-outline btn-sm view-details" data-id="${item.id}">
                    Подробнее
                </button>
            </td>
        `;

        row.querySelector('.view-details').addEventListener('click', () => {
            this.showVulnerabilityDetails(item);
        });

        return row;
    }

    showVulnerabilityDetails(item) {
        const modal = document.getElementById('vulnerabilityModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalContent = document.getElementById('modalContent');

        if (!modal || !modalTitle || !modalContent) return;

        modalTitle.textContent = item.vulnerabilityTitle;

        // Форматируем рекомендации с поддержкой многострочности
        const formatRecommendations = (recText) => {
            if (!recText) return 'Нет рекомендаций';

            // Если рекомендации содержат маркированный список
            if (recText.includes('\n') || recText.includes('•') || recText.includes('-')) {
                let formatted = recText
                    .replace(/\n/g, '<br>')
                    .replace(/•/g, '•')
                    .replace(/-/g, '•');
                return formatted;
            }
            return recText;
        };

        modalContent.innerHTML = `
            <div class="vulnerability-details">
                <div class="detail-group">
                    <label>Банк:</label>
                    <span>${this.escapeHtml(item.bankName)}</span>
                </div>
                <div class="detail-group">
                    <label>Уровень критичности:</label>
                    <span class="severity-badge severity-${item.severity.toLowerCase()}">${item.severity}</span>
                </div>
                <div class="detail-group">
                    <label>Категория:</label>
                    <span>${this.escapeHtml(item.category)}</span>
                </div>
                <div class="detail-group">
                    <label>Статус код:</label>
                    <span>${this.escapeHtml(item.statusCode === "-1" ? "N/A" : item.statusCode)}</span>
                </div>
                <div class="detail-group">
                    <label>Сканер:</label>
                    <span>${this.escapeHtml(item.scannerName || 'N/A')}</span>
                </div>
                <div class="detail-group">
                    <label>Дата обнаружения:</label>
                    <span>${new Date(item.scanDate).toLocaleString('ru-RU')}</span>
                </div>
                <div class="detail-group">
                    <label>Доказательство:</label>
                    <div class="proof">${this.formatProof(item.proof || 'Нет информации')}</div>
                </div>
                <div class="detail-group">
                    <label>Рекомендации:</label>
                    <div class="recommendation" style="white-space: pre-line; line-height: 1.5;">${formatRecommendations(item.recommendation)}</div>
                </div>
            </div>
        `;

        modal.style.display = 'block';
    }

    closeModal() {
        const modal = document.getElementById('vulnerabilityModal');
        if (modal) modal.style.display = 'none';
    }

    updatePagination() {
        const totalPages = Math.ceil(this.filteredData.length / this.pageSize);
        const pageInfo = document.getElementById('pageInfo');
        const prevButton = document.getElementById('prevPage');
        const nextButton = document.getElementById('nextPage');

        if (pageInfo) pageInfo.textContent = `Страница ${this.currentPage} из ${totalPages}`;
        if (prevButton) prevButton.disabled = this.currentPage === 1;
        if (nextButton) nextButton.disabled = this.currentPage === totalPages || totalPages === 0;
    }

    previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.renderTable();
            this.saveState();
        }
    }

    nextPage() {
        const totalPages = Math.ceil(this.filteredData.length / this.pageSize);
        if (this.currentPage < totalPages) {
            this.currentPage++;
            this.renderTable();
            this.saveState();
        }
    }

    showNotification(message, type = 'info') {
        const notifications = document.getElementById('notifications');
        if (!notifications) return;

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;

        notifications.appendChild(notification);

        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
    }

    setupBankCards() {
        // Обработчик для кнопки добавления банка
        document.getElementById('addBankBtn').addEventListener('click', () => {
            this.addBankCard();
        });

        // Обработчики для удаления банков (делегирование событий)
        document.getElementById('bankCardsContainer').addEventListener('click', (e) => {
            if (e.target.classList.contains('btn-remove-bank')) {
                this.removeBankCard(e.target.closest('.bank-config'));
            }
        });

        // Инициализация одной карточки по умолчанию
        if (document.getElementById('bankCardsContainer').children.length === 0) {
            this.addBankCard();
        }
    }

    addBankCard(bankData = { baseUrl: '', specUrl: '' }) {
        const container = document.getElementById('bankCardsContainer');
        const bankIndex = container.children.length + 1;

        const bankCard = document.createElement('div');
        bankCard.className = 'bank-config';
        bankCard.setAttribute('data-bank-index', bankIndex);

        bankCard.innerHTML = `
            <div class="bank-header">
                <h4>Банк ${bankIndex}</h4>
                ${bankIndex > 1 ? '<button class="btn-remove-bank" type="button">×</button>' : ''}
            </div>
            <div class="input-group">
                <label>Base URL:</label>
                <input type="text" class="config-input bank-url"
                       value="${bankData.baseUrl}" placeholder="URL">
            </div>
            <div class="input-group">
                <label>OpenAPI Spec URL:</label>
                <input type="text" class="config-input bank-spec"
                       value="${bankData.specUrl}" placeholder="URL к спецификации">
            </div>
        `;

        container.appendChild(bankCard);
    }

    removeBankCard(bankCard) {
        if (document.getElementById('bankCardsContainer').children.length > 1) {
            bankCard.remove();
            this.renumberBankCards();
        } else {
            this.showNotification('Должен остаться хотя бы один банк', 'warning');
        }
    }

    renumberBankCards() {
        const container = document.getElementById('bankCardsContainer');
        const bankCards = container.querySelectorAll('.bank-config');

        bankCards.forEach((card, index) => {
            const newIndex = index + 1;
            card.setAttribute('data-bank-index', newIndex);
            card.querySelector('h4').textContent = `Банк ${newIndex}`;

            // Показываем/скрываем кнопку удаления
            const removeBtn = card.querySelector('.btn-remove-bank');
            if (removeBtn) {
                removeBtn.style.display = newIndex > 1 ? 'block' : 'none';
            }
        });
    }

    exportToCsv() {
        if (this.filteredData.length === 0) {
            this.showNotification('Нет данных для экспорта', 'error');
            return;
        }

        const headers = ['Банк', 'Уязвимость', 'Уровень', 'Категория', 'Статус', 'Дата', 'Доказательство', 'Рекомендации'];
        const csvData = this.filteredData.map(item => [
            item.bankName,
            item.vulnerabilityTitle,
            item.severity,
            item.category,
            item.statusCode || 'N/A',
            new Date(item.scanDate).toLocaleDateString('ru-RU'),
            `"${(item.proof || '').replace(/"/g, '""')}"`,
            `"${(item.recommendation || '').replace(/"/g, '""')}"`
        ]);

        const csvContent = [headers, ...csvData].map(row => row.join(',')).join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);

        link.setAttribute('href', url);
        link.setAttribute('download', `security_scan_${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        this.showNotification('Данные экспортированы в CSV', 'success');
    }

    exportToPdf() {
        if (this.filteredData.length === 0) {
            this.showNotification('Нет данных для экспорта', 'error');
            return;
        }

        this.showNotification('Генерация PDF отчета...', 'info');

        // Создаем URL с параметрами фильтров
        const params = new URLSearchParams();
        if (this.filters.severity) params.append('severity', this.filters.severity);
        if (this.filters.category) params.append('category', this.filters.category);
        if (this.filters.bank) params.append('bank', this.filters.bank);

        const url = `/api/scan/export/pdf?${params.toString()}`;

        // Создаем временную ссылку для скачивания
        const link = document.createElement('a');
        link.href = url;
        link.download = `security_scan_${new Date().toISOString().split('T')[0]}.pdf`;
        link.style.visibility = 'hidden';

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        this.showNotification('PDF отчет успешно сгенерирован', 'success');
    }

    formatProof(text) {
        try {
            const obj = JSON.parse(text);
            return this.syntaxHighlight(JSON.stringify(obj, null, 2));
        } catch (e) {
            return this.escapeHtml(text);
        }
    }

    syntaxHighlight(json) {
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) cls = 'key';
                else cls = 'string';
            } else if (/true|false/.test(match)) cls = 'boolean';
            else if (/null/.test(match)) cls = 'null';
            return '<span class="' + cls + '">' + match + '</span>';
        });
    }

    escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return unsafe.toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Методы для сравнения сессий

    // Загрузка списка сессий
    async loadSessionsList() {
        try {
            const response = await fetch('/api/sessions/list');
            if (response.ok) {
                const sessions = await response.json();
                this.sessions = sessions;
                this.populateSessionSelects(sessions);
            }
        } catch (error) {
            console.error('Error loading sessions:', error);
            this.showNotification('Ошибка загрузки списка сессий', 'error');
        }
    }

    // Заполнение выпадающих списков сессиями
    async populateSessionSelects(sessions) {
        const session1Select = document.getElementById('session1Select');
        const session2Select = document.getElementById('session2Select');

        // Очищаем существующие опции (кроме первой)
        while (session1Select.children.length > 1) session1Select.removeChild(session1Select.lastChild);
        while (session2Select.children.length > 1) session2Select.removeChild(session2Select.lastChild);

        // Сортируем сессии по дате (новые сначала)
        sessions.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));

        // Для каждой сессии получаем реальное количество уязвимостей
        const sessionsWithRealCounts = await Promise.all(
            sessions.map(async (session) => {
                try {
                    const response = await fetch(`/api/scan/results?session=${session.sessionId}`);
                    if (response.ok) {
                        const vulnerabilities = await response.json();
                        return {
                            ...session,
                            realVulnerabilitiesCount: vulnerabilities.length
                        };
                    }
                } catch (error) {
                    console.error(`Error getting vulnerabilities for session ${session.sessionId}:`, error);
                }
                return {
                    ...session,
                    realVulnerabilitiesCount: session.vulnerabilitiesCount || 0
                };
            })
        );

        sessionsWithRealCounts.forEach(session => {
            const option1 = document.createElement('option');
            const option2 = document.createElement('option');

            const sessionDate = new Date(session.startTime).toLocaleDateString('ru-RU');
            const sessionTime = new Date(session.startTime).toLocaleTimeString('ru-RU', {
                hour: '2-digit',
                minute: '2-digit'
            });

            // Используем реальное количество уязвимостей
            const vulnCount = session.realVulnerabilitiesCount || session.vulnerabilitiesCount || 0;

            option1.value = session.sessionId;
            option1.textContent = `${session.sessionName} (${sessionDate} ${sessionTime}) - ${vulnCount} уязвимостей`;

            option2.value = session.sessionId;
            option2.textContent = `${session.sessionName} (${sessionDate} ${sessionTime}) - ${vulnCount} уязвимостей`;

            session1Select.appendChild(option1);
            session2Select.appendChild(option2);
        });
    }

    // Основной метод сравнения сессий
    async compareSessions() {
        const session1Id = document.getElementById('session1Select').value;
        const session2Id = document.getElementById('session2Select').value;

        if (!session1Id || !session2Id) {
            this.showNotification('Выберите обе сессии для сравнения', 'error');
            return;
        }

        if (session1Id === session2Id) {
            this.showNotification('Выберите разные сессии для сравнения', 'error');
            return;
        }

        try {
            this.showNotification('Сравниваю сессии...', 'info');

            const response = await fetch(`/api/sessions/compare?session1=${session1Id}&session2=${session2Id}`);
            if (response.ok) {
                const comparisonData = await response.json();
                this.displayComparisonResults(comparisonData, session1Id, session2Id);
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            console.error('Error comparing sessions:', error);
            this.showNotification('Ошибка при сравнении сессий', 'error');
        }
    }

    // Отображение результатов сравнения
    displayComparisonResults(comparison, session1Id, session2Id) {
        const resultsContainer = document.getElementById('comparisonResults');
        resultsContainer.style.display = 'block';
        resultsContainer.innerHTML = this.generateComparisonHTML(comparison, session1Id, session2Id);

        // Прокрутка к результатам
        resultsContainer.scrollIntoView({ behavior: 'smooth' });

        this.showNotification('Сравнение завершено', 'success');
    }

    // Генерация HTML для результатов сравнения
    generateComparisonHTML(comparison, session1Id, session2Id) {
        const session1Name = document.getElementById('session1Select').selectedOptions[0].text;
        const session2Name = document.getElementById('session2Select').selectedOptions[0].text;

        // Вычисляем общее количество уязвимостей для каждой сессии
        const session1Total = Object.values(comparison.session1Stats || {}).reduce((sum, val) => sum + val, 0);
        const session2Total = Object.values(comparison.session2Stats || {}).reduce((sum, val) => sum + val, 0);
        const totalDiff = session2Total - session1Total;

        return `
            <div class="comparison-results">
                <h4>Результаты сравнения сессий сканирования</h4>

                <!-- Сводная статистика -->
                <div class="comparison-stats">
                    <div class="comparison-stat-card">
                        <div class="comparison-stat-label">Новые уязвимости</div>
                        <div class="comparison-stat-value comparison-diff-positive">+${comparison.newCount || 0}</div>
                        <div>Появились во второй сессии</div>
                    </div>

                    <div class="comparison-stat-card">
                        <div class="comparison-stat-label">Исправленные уязвимости</div>
                        <div class="comparison-stat-value comparison-diff-negative">-${comparison.fixedCount || 0}</div>
                        <div>Устранены во второй сессии</div>
                    </div>

                    <div class="comparison-stat-card">
                        <div class="comparison-stat-label">Критические уязвимости</div>
                        <div class="comparison-stat-value ${this.getDiffClass((comparison.session2Stats?.CRITICAL || 0) - (comparison.session1Stats?.CRITICAL || 0))}">
                            ${this.formatDiff((comparison.session2Stats?.CRITICAL || 0) - (comparison.session1Stats?.CRITICAL || 0))}
                        </div>
                        <div>${comparison.session1Stats?.CRITICAL || 0} → ${comparison.session2Stats?.CRITICAL || 0}</div>
                    </div>

                    <div class="comparison-stat-card">
                        <div class="comparison-stat-label">Общее изменение</div>
                        <div class="comparison-stat-value ${this.getDiffClass(totalDiff)}">
                            ${this.formatDiff(totalDiff)}
                        </div>
                        <div>${session1Total} → ${session2Total}</div>
                    </div>
                </div>

                <!-- Графики сравнения -->
                <div class="comparison-charts">
                    <div class="chart-wrapper">
                        <h5>${this.shortenSessionName(session1Name)}</h5>
                        <div class="chart">
                            ${this.generateSeverityComparisonChart(comparison.session1Stats)}
                        </div>
                    </div>

                    <div class="chart-wrapper">
                        <h5>${this.shortenSessionName(session2Name)}</h5>
                        <div class="chart">
                            ${this.generateSeverityComparisonChart(comparison.session2Stats)}
                        </div>
                    </div>
                </div>

                <!-- Новые уязвимости -->
                ${comparison.newVulnerabilities && comparison.newVulnerabilities.length > 0 ? `
                <div class="comparison-vulnerabilities">
                    <h5>Новые уязвимости (${comparison.newCount})</h5>
                    <div class="vulnerability-change-list">
                        ${comparison.newVulnerabilities.map(vuln => `
                            <div class="vulnerability-change-item">
                                <div class="vulnerability-change-info">
                                    <div class="vulnerability-change-title">${this.escapeHtml(vuln.vulnerabilityTitle)}</div>
                                    <div class="vulnerability-change-meta">
                                        ${this.escapeHtml(vuln.bankName)} • ${vuln.category} • ${vuln.severity} • ${new Date(vuln.scanDate).toLocaleDateString('ru-RU')}
                                    </div>
                                </div>
                                <span class="change-badge change-new">НОВАЯ</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                <!-- Исправленные уязвимости -->
                ${comparison.fixedVulnerabilities && comparison.fixedVulnerabilities.length > 0 ? `
                <div class="comparison-vulnerabilities">
                    <h5>Исправленные уязвимости (${comparison.fixedCount})</h5>
                    <div class="vulnerability-change-list">
                        ${comparison.fixedVulnerabilities.map(vuln => `
                            <div class="vulnerability-change-item">
                                <div class="vulnerability-change-info">
                                    <div class="vulnerability-change-title">${this.escapeHtml(vuln.vulnerabilityTitle)}</div>
                                    <div class="vulnerability-change-meta">
                                        ${this.escapeHtml(vuln.bankName)} • ${vuln.category} • ${vuln.severity} • ${new Date(vuln.scanDate).toLocaleDateString('ru-RU')}
                                    </div>
                                </div>
                                <span class="change-badge change-fixed">ИСПРАВЛЕНА</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                ${(!comparison.newVulnerabilities || comparison.newVulnerabilities.length === 0) &&
                  (!comparison.fixedVulnerabilities || comparison.fixedVulnerabilities.length === 0) ? `
                    <div class="no-data" style="text-align: center; padding: 2rem;">
                        Нет изменений между выбранными сессиями
                    </div>
                ` : ''}
            </div>
        `;
    }

    // Вспомогательные методы для сравнения
    shortenSessionName(fullName) {
        return fullName.length > 50 ? fullName.substring(0, 50) + '...' : fullName;
    }

    // Методы для графа API:
    async loadApiGraph() {
        const specUrl = document.getElementById('specUrlInput').value;

        if (!specUrl) {
            this.showNotification('Введите URL OpenAPI спецификации', 'error');
            return;
        }

        try {
            this.showNotification('Загрузка графа API...', 'info');

            const response = await fetch(`/api/graph?spec=${encodeURIComponent(specUrl)}`);
            if (response.ok) {
                const graphData = await response.json();
                this.renderApiGraph(graphData);
                this.showNotification(`Загружено ${graphData.totalEndpoints} эндпоинтов`, 'success');
            } else {
                throw new Error('Failed to load graph');
            }
        } catch (error) {
            console.error('Error loading API graph:', error);
            this.showNotification('Ошибка загрузки графа API', 'error');
        }
    }

    renderApiGraph(graphData) {
        const container = document.getElementById('network');
        if (!container) return;

        // Очищаем предыдущий граф
        container.innerHTML = '';

        if (!graphData.nodes || graphData.nodes.length === 0) {
            container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #94a3b8;">Нет данных для отображения</div>';
            return;
        }

        // Форматируем данные для vis.js
        const nodes = new vis.DataSet(graphData.nodes.map(node => ({
            id: node.id,
            label: node.label,
            title: node.title || node.path,
            group: node.group,
            color: node.color,
            font: { color: '#ffffff', size: 12 },
            borderWidth: 2
        })));

        const edges = new vis.DataSet(graphData.edges.map(edge => ({
            from: edge.from,
            to: edge.to,
            color: edge.color,
            width: 1
        })));

        const data = { nodes, edges };

        const options = {
            nodes: {
                shape: 'dot',
                size: 20,
                font: {
                    size: 12,
                    face: 'Inter',
                    color: '#ffffff'
                },
                borderWidth: 2,
                shadow: true
            },
            edges: {
                width: 1,
                color: { color: '#334155' },
                smooth: {
                    type: 'continuous'
                },
                shadow: true
            },
            groups: {
                default: { color: { background: '#3b82f6', border: '#2563eb' } },
                auth: { color: { background: '#ef4444', border: '#dc2626' } },
                accounts: { color: { background: '#10b981', border: '#059669' } },
                payments: { color: { background: '#f59e0b', border: '#d97706' } },
                transfers: { color: { background: '#8b5cf6', border: '#7c3aed' } }
            },
            physics: {
                enabled: true,
                stabilization: { iterations: 100 },
                barnesHut: {
                    gravitationalConstant: -8000,
                    springConstant: 0.04,
                    springLength: 95
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200
            },
            layout: {
                improvedLayout: true
            }
        };

        // Создаем сеть
        this.currentGraph = new vis.Network(container, data, options);

        // Обработчик клика по узлу
        this.currentGraph.on("click", (params) => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const node = graphData.nodes.find(n => n.id === nodeId);
                if (node) {
                    this.showEndpointDetails(node, graphData);
                }
            }
        });

        // Обработчик двойного клика - центрирование
        this.currentGraph.on("doubleClick", (params) => {
            if (params.nodes.length > 0) {
                this.currentGraph.focus(params.nodes[0], { scale: 1.2 });
            }
        });
    }

    showEndpointDetails(node, graphData) {
        const panel = document.getElementById('endpointPanel');
        const info = document.getElementById('endpointInfo');

        // Форматируем информацию об эндпоинте
        let html = `
            <div style="margin-bottom: 15px;">
                <h4 style="color: #3b82f6; margin-bottom: 10px;">${node.method} ${node.path}</h4>
                ${node.summary ? `<p><strong>Описание:</strong> ${this.escapeHtml(node.summary)}</p>` : ''}
                ${node.description ? `<p><strong>Детали:</strong> ${this.escapeHtml(node.description)}</p>` : ''}
                <p><strong>Группа:</strong> ${node.group || 'default'}</p>
            </div>
        `;

        info.innerHTML = html;

        // Устанавливаем данные для тестирования
        document.getElementById('testMethod').value = node.method;
        document.getElementById('testUrl').value = node.path;

        panel.style.display = 'block';

        // Прокручиваем к панели
        panel.scrollIntoView({ behavior: 'smooth' });
    }

    hideEndpointPanel() {
        document.getElementById('endpointPanel').style.display = 'none';
        document.getElementById('testResult').style.display = 'none';
    }

    async testEndpoint() {
        const method = document.getElementById('testMethod').value;
        const path = document.getElementById('testUrl').value;
        const baseUrl = document.getElementById('baseUrlInput').value;
        const headersText = document.getElementById('headersInput').value;
        const bodyText = document.getElementById('bodyInput').value;

        if (!baseUrl) {
            this.showNotification('Введите базовый URL', 'error');
            return;
        }

        const fullUrl = baseUrl + path;

        try {
            this.showNotification('Выполняю запрос...', 'info');

            let headers = {};
            if (headersText) {
                headers = JSON.parse(headersText);
            }

            let body = null;
            if (bodyText && method !== 'GET') {
                body = bodyText;
            }

            const testData = {
                method: method,
                url: fullUrl,
                headers: headers,
                body: body
            };

            const response = await fetch('/api/test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(testData)
            });

            const result = await response.json();

            // Показываем результат
            const resultOutput = document.getElementById('resultOutput');
            const testResult = document.getElementById('testResult');

            resultOutput.textContent = JSON.stringify(result, null, 2);
            testResult.style.display = 'block';

            this.showNotification('Запрос выполнен', 'success');

        } catch (error) {
            console.error('Error testing endpoint:', error);
            this.showNotification('Ошибка выполнения запроса', 'error');

            const resultOutput = document.getElementById('resultOutput');
            const testResult = document.getElementById('testResult');

            resultOutput.textContent = `Error: ${error.message}`;
            testResult.style.display = 'block';
        }
    }

    getDiffClass(diff) {
        if (diff > 0) return 'comparison-diff-positive';
        if (diff < 0) return 'comparison-diff-negative';
        return 'comparison-diff-neutral';
    }

    formatDiff(diff) {
        if (diff > 0) return `+${diff}`;
        if (diff < 0) return `${diff}`;
        return '0';
    }

    generateSeverityComparisonChart(stats) {
        if (!stats || Object.keys(stats).length === 0) {
            return '<div class="chart-placeholder">Нет данных</div>';
        }

        const total = Object.values(stats).reduce((sum, val) => sum + val, 0) || 1;
        const severities = [
            { label: 'Критические', key: 'CRITICAL', color: '#ef4444' },
            { label: 'Высокие', key: 'HIGH', color: '#f59e0b' },
            { label: 'Средние', key: 'MEDIUM', color: '#eab308' },
            { label: 'Низкие', key: 'LOW', color: '#10b981' }
        ];

        const chartData = severities
            .map(sev => ({
                ...sev,
                value: stats[sev.key] || 0,
                percent: ((stats[sev.key] || 0) / total * 100)
            }))
            .filter(item => item.value > 0);

        if (chartData.length === 0) {
            return '<div class="chart-placeholder">Нет данных</div>';
        }

        return `
            <div class="simple-chart">
                ${chartData.map(item => `
                    <div class="chart-item">
                        <div class="chart-bar-container">
                            <div class="chart-bar" style="width: ${item.percent}%; background: ${item.color};"></div>
                            <span class="chart-value">${item.value}</span>
                        </div>
                        <div class="chart-label">
                            <span class="chart-color" style="background: ${item.color}"></span>
                            ${item.label} (${item.percent.toFixed(1)}%)
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecurityDashboard();
});