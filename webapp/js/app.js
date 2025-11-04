class SecurityDashboard {
    constructor() {
        this.currentData = [];
        this.filteredData = [];
        this.currentPage = 1;
        this.pageSize = 20;
        this.filters = {};
        this.socket = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.connectWebSocket();
        this.loadInitialData();
    }

    setupEventListeners() {
        // Кнопка запуска сканирования
        document.getElementById('startScanBtn').addEventListener('click', () => {
            this.startScan();
        });

        // Фильтры
        document.getElementById('applyFilters').addEventListener('click', () => {
            this.applyFilters();
        });

        document.getElementById('clearFilters').addEventListener('click', () => {
            this.clearFilters();
        });

        // Пагинация
        document.getElementById('prevPage').addEventListener('click', () => {
            this.previousPage();
        });

        document.getElementById('nextPage').addEventListener('click', () => {
            this.nextPage();
        });

        // Экспорт
        document.getElementById('exportCsv').addEventListener('click', () => {
            this.exportToCsv();
        });

        // Модальное окно
        document.querySelector('.close').addEventListener('click', () => {
            this.closeModal();
        });

        window.addEventListener('click', (e) => {
            if (e.target === document.getElementById('vulnerabilityModal')) {
                this.closeModal();
            }
        });
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/scanner`;

        try {
            this.socket = new WebSocket(wsUrl);

            this.socket.onopen = () => {
                console.log('WebSocket connected');
                this.updateConnectionStatus('online');
                this.showNotification('Соединение установлено', 'success');
            };

            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (e) {
                    console.error('Error parsing WebSocket message:', e);
                }
            };

            this.socket.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus('offline');
                // Попытка переподключения через 5 секунд
                setTimeout(() => this.connectWebSocket(), 5000);
            };

            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('error');
            };
        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.updateConnectionStatus('error');
        }
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'NEW_VULNERABILITY':
                this.addNewVulnerability(message.data);
                break;
            case 'SCAN_STARTED':
                this.showNotification('Сканирование запущено', 'info');
                break;
            case 'SCAN_COMPLETED':
                this.showNotification('Сканирование завершено', 'success');
                this.loadInitialData(); // Перезагружаем все данные
                break;
            default:
                console.log('Unknown message type:', message.type);
        }
    }

    updateConnectionStatus(status) {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            statusElement.className = `status-${status}`;
            statusElement.textContent = `● ${this.getStatusText(status)}`;
        }
    }

    getStatusText(status) {
        const statusMap = {
            online: 'Online',
            offline: 'Offline',
            error: 'Error',
            connecting: 'Connecting...'
        };
        return statusMap[status] || 'Unknown';
    }

    async loadInitialData() {
        try {
            const response = await fetch('/api/scan/results');
            if (response.ok) {
                this.currentData = await response.json();
                this.filteredData = [...this.currentData];
                this.renderTable();
                this.updateStats();
                this.populateFilters();
            } else {
                throw new Error('Failed to load data');
            }
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showNotification('Ошибка загрузки данных', 'error');
        }
    }

    async updateStats() {
        try {
            // Простая статистика на основе текущих данных
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
        } catch (error) {
            console.error('Error updating stats:', error);
        }
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
            chart.innerHTML = '<div class="chart-placeholder">Нет данных для отображения</div>';
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
            .slice(0, 8); // Топ-8 категорий

        if (data.length === 0) {
            chart.innerHTML = '<div class="chart-placeholder">Нет данных для отображения</div>';
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
            'OWASP_API10_UNSAFE_CONSUMPTION': 'API10 - Unsafe Consumption'
        };
        return shortNames[name] || name.substring(0, 20) + (name.length > 20 ? '...' : '');
    }

    populateFilters() {
        const categoryFilter = document.getElementById('categoryFilter');
        const bankFilter = document.getElementById('bankFilter');

        if (!categoryFilter || !bankFilter) return;

        // Очищаем существующие опции (кроме первой)
        while (categoryFilter.children.length > 1) {
            categoryFilter.removeChild(categoryFilter.lastChild);
        }
        while (bankFilter.children.length > 1) {
            bankFilter.removeChild(bankFilter.lastChild);
        }

        // Получаем уникальные категории и банки
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
    }

    applyFilters() {
        const severity = document.getElementById('severityFilter').value;
        const category = document.getElementById('categoryFilter').value;
        const bank = document.getElementById('bankFilter').value;

        this.filters = {};
        if (severity) this.filters.severity = severity;
        if (category) this.filters.category = category;
        if (bank) this.filters.bank = bank;

        this.filteredData = this.currentData.filter(item => {
            return (
                (!this.filters.severity || item.severity === this.filters.severity) &&
                (!this.filters.category || item.category === this.filters.category) &&
                (!this.filters.bank || item.bankName === this.filters.bank)
            );
        });

        this.currentPage = 1;
        this.renderTable();
    }

    clearFilters() {
        document.getElementById('severityFilter').value = '';
        document.getElementById('categoryFilter').value = '';
        document.getElementById('bankFilter').value = '';
        this.filters = {};
        this.filteredData = [...this.currentData];
        this.currentPage = 1;
        this.renderTable();
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

        // Добавляем обработчик для кнопки подробнее
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
                    <div class="proof">
                        ${this.formatProof(item.proof || 'Нет информации')}
                    </div>
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
        if (modal) {
            modal.style.display = 'none';
        }
    }

    updatePagination() {
        const totalPages = Math.ceil(this.filteredData.length / this.pageSize);
        const pageInfo = document.getElementById('pageInfo');
        const prevButton = document.getElementById('prevPage');
        const nextButton = document.getElementById('nextPage');

        if (pageInfo) {
            pageInfo.textContent = `Страница ${this.currentPage} из ${totalPages}`;
        }

        if (prevButton) {
            prevButton.disabled = this.currentPage === 1;
        }

        if (nextButton) {
            nextButton.disabled = this.currentPage === totalPages || totalPages === 0;
        }
    }

    previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.renderTable();
        }
    }

    nextPage() {
        const totalPages = Math.ceil(this.filteredData.length / this.pageSize);
        if (this.currentPage < totalPages) {
            this.currentPage++;
            this.renderTable();
        }
    }

    addNewVulnerability(vulnerability) {
        // Добавляем новую уязвимость в начало списка
        this.currentData.unshift(vulnerability);

        // Применяем текущие фильтры
        if (this.passesFilters(vulnerability)) {
            this.filteredData.unshift(vulnerability);
            // Если мы на первой странице, обновляем таблицу
            if (this.currentPage === 1) {
                this.renderTable();
            }
        }

        this.updateStats();
        this.showNewVulnerabilityNotification(vulnerability);
    }

    passesFilters(vulnerability) {
        return (
            (!this.filters.severity || vulnerability.severity === this.filters.severity) &&
            (!this.filters.category || vulnerability.category === this.filters.category) &&
            (!this.filters.bank || vulnerability.bankName === this.filters.bank)
        );
    }

    showNewVulnerabilityNotification(vulnerability) {
        const notifications = document.getElementById('notifications');
        if (!notifications) return;

        const notification = document.createElement('div');
        notification.className = `notification ${vulnerability.severity.toLowerCase()}`;
        notification.innerHTML = `
            <strong>Новая уязвимость</strong>
            <div>${this.escapeHtml(vulnerability.vulnerabilityTitle)}</div>
            <small>Банк: ${this.escapeHtml(vulnerability.bankName)} | Уровень: ${vulnerability.severity}</small>
        `;

        notifications.appendChild(notification);

        // Автоматическое удаление через 5 секунд
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
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
        }, 3000);
    }

    async startScan() {
        try {
            const banks = [
                'https://vbank.open.bankingapi.ru',
                'https://abank.open.bankingapi.ru',
                'https://sbank.open.bankingapi.ru'
            ];

            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ banks })
            });

            if (response.ok) {
                this.showNotification('Сканирование запущено', 'success');
                // Очищаем текущие данные
                this.currentData = [];
                this.filteredData = [];
                this.renderTable();
                this.updateStats();
            } else {
                throw new Error('Server responded with error');
            }
        } catch (error) {
            console.error('Error starting scan:', error);
            this.showNotification('Ошибка запуска сканирования', 'error');
        }
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

        const csvContent = [headers, ...csvData]
            .map(row => row.join(','))
            .join('\n');

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
            // Пытаемся распарсить JSON для красивого форматирования
            const obj = JSON.parse(text);
            return this.syntaxHighlight(JSON.stringify(obj, null, 2));
        } catch (e) {
            // Если это не JSON, просто возвращаем текст с экранированием
            return this.escapeHtml(text);
        }
    }

    syntaxHighlight(json) {
        json = json.replace(/&/g, '&amp;').replace(/</g, '<').replace(/>/g, '>');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'key';
                } else {
                    cls = 'string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'boolean';
            } else if (/null/.test(match)) {
                cls = 'null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    }

    escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecurityDashboard();
});