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
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.connectWebSocket();
        this.loadInitialData();

        // Восстанавливаем состояние из localStorage при загрузке
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

        // Сохраняем состояние при закрытии страницы
        window.addEventListener('beforeunload', () => {
            this.saveState();
        });
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

    // Добавляем метод для сохранения состояния
    saveState() {
        const state = {
            filters: this.filters,
            currentPage: this.currentPage,
            pageSize: this.pageSize
        };
        localStorage.setItem('dashboardState', JSON.stringify(state));
    }

    // Добавляем метод для восстановления состояния
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

        try {
            this.isScanning = true;
            this.updateScanButton(true);
            this.showNotification('Сканирование запущено', 'success');
            this.lastDataCount = this.currentData.length;

            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Server error');
            }

            this.showNotification('Ожидайте первые результаты сканирования...', 'info');

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
            btn.innerHTML = '<span class="scanning-indicator"><span class="pulse">⏳</span> Сканирование...</span>';
            btn.disabled = true;
        } else {
            btn.innerHTML = '🚀 Запустить сканирование';
            btn.disabled = false;
        }
        this.updateConnectionStatus();
    }

    updateConnectionStatus() {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            if (this.isScanning) {
                statusElement.className = 'status-connecting';
                statusElement.textContent = '● Сканирование...';
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
            'OWASP_API10_UNSAFE_CONSUMPTION': 'API10 - Unsafe Consumption'
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
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecurityDashboard();
});