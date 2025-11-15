class SecurityDashboard {
    constructor() {
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
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupConfigListeners();
        this.connectWebSocket();
        this.loadInitialData();
        this.restoreState();
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

        document.querySelector('.close').addEventListener('click', () => {
            this.closeModal();
        });

        window.addEventListener('click', (e) => {
            if (e.target === document.getElementById('vulnerabilityModal')) {
                this.closeModal();
            }
        });

        // Новые обработчики для сравнения
        document.getElementById('showComparison').addEventListener('click', () => {
            this.showComparisonSection();
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

    async clearDatabase() {
        if (!confirm('Вы уверены, что хотите полностью очистить базу данных? Это действие нельзя отменить.')) {
            return;
        }

        try {
            this.showNotification('🔄 Очистка базы данных...', 'info');

            const response = await fetch('/api/scan/clear', {
                method: 'POST'
            });

            if (response.ok) {
                this.showNotification('✅ База данных успешно очищена', 'success');
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
            this.showNotification('❌ Ошибка при очистке базы данных', 'error');
        }
    }

    saveConfiguration() {
        const config = {
            banks: [
                {
                    baseUrl: document.getElementById('bank1Url').value.trim(),
                    specUrl: document.getElementById('bank1Spec').value.trim()
                },
                {
                    baseUrl: document.getElementById('bank2Url').value.trim(),
                    specUrl: document.getElementById('bank2Spec').value.trim()
                },
                {
                    baseUrl: document.getElementById('bank3Url').value.trim(),
                    specUrl: document.getElementById('bank3Spec').value.trim()
                }
            ],
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

        // Валидация
        if (!this.validateConfiguration(config)) {
            return;
        }

        // Сохраняем в localStorage
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
            banks: [
                {
                    baseUrl: "https://vbank.open.bankingapi.ru",
                    specUrl: "https://vbank.open.bankingapi.ru/openapi.json"
                },
                {
                    baseUrl: "https://abank.open.bankingapi.ru",
                    specUrl: "https://abank.open.bankingapi.ru/openapi.json"
                },
                {
                    baseUrl: "https://sbank.open.bankingapi.ru",
                    specUrl: "https://sbank.open.bankingapi.ru/openapi.json"
                }
            ],
            credentials: [
                {
                    username: "team172-8",
                    password: "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY"
                },
                {
                    username: "team172-9",
                    password: "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY"
                }
            ]
        };

        this.applyConfiguration(defaultConfig);
        this.showNotification('Настройки по умолчанию загружены', 'info');
    }

    applyConfiguration(config) {
        // Применяем настройки к форме
        config.banks.forEach((bank, index) => {
            document.getElementById(`bank${index + 1}Url`).value = bank.baseUrl;
            document.getElementById(`bank${index + 1}Spec`).value = bank.specUrl;
        });

        config.credentials.forEach((cred, index) => {
            document.getElementById(`user${index + 1}`).value = cred.username;
            document.getElementById(`password${index + 1}`).value = cred.password;
        });
    }

    validateConfiguration(config) {
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
            const saved = localStorage.getItem('scanConfig');
            return saved ? JSON.parse(saved) : null;
        } catch (e) {
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
            this.isScanning = true;
            this.updateScanButton(true);
            this.showNotification('🔄 Запущено расширенное сканирование с новыми типами атак', 'success');
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

            this.showNotification('🔍 Сканирование запущено. Ожидайте первые результаты...', 'info');

        } catch (error) {
            console.error('Error starting scan:', error);
            this.showNotification('Ошибка запуска сканирования', 'error');
            this.isScanning = false;
            this.updateScanButton(false);
        }
    }

    updateScanButton(scanning) {
        const btn = document.getElementById('startScanBtn');
        if (scanning) {
            btn.innerHTML = '<span class="scanning-indicator"><span class="pulse">⏳</span> Расширенное сканирование...</span>';
            btn.disabled = true;
        } else {
            btn.innerHTML = '🚀 Запустить расширенное сканирование';
            btn.disabled = false;
        }
        this.updateConnectionStatus();
    }

    updateConnectionStatus() {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            if (this.isScanning) {
                statusElement.className = 'status-connecting';
                statusElement.textContent = '● Расширенное сканирование...';
            } else {
                statusElement.className = 'status-online';
                statusElement.textContent = '● Online';
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
            .slice(0, 8);

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
                    👁️ Подробнее
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
                    <span>${this.escapeHtml(item.statusCode || 'N/A')}</span>
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
                    <div class="recommendation">${this.escapeHtml(item.recommendation || 'Нет рекомендаций')}</div>
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

    // Метод для показа секции сравнения
    async showComparisonSection() {
        document.getElementById('comparisonSection').style.display = 'block';
        document.querySelector('.dashboard').style.display = 'none';

        await this.loadSessionsList();
        this.showNotification('Выберите две сессии для сравнения', 'info');
    }

    // Метод для скрытия секции сравнения
    hideComparisonSection() {
        document.getElementById('comparisonSection').style.display = 'none';
        document.querySelector('.dashboard').style.display = 'block';
        document.getElementById('comparisonResults').style.display = 'none';
    }

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
            this.showNotification('🔄 Сравниваю сессии...', 'info');

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

        this.showNotification('✅ Сравнение завершено', 'success');
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
                <h4>📊 Результаты сравнения сессий сканирования</h4>

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
                    <h5>🆕 Новые уязвимости (${comparison.newCount})</h5>
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
                    <h5>✅ Исправленные уязвимости (${comparison.fixedCount})</h5>
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