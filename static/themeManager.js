class ThemeManager {
    constructor() {
        this.currentTheme = 'auto';
        this.systemTheme = 'dark';
        this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        this.savedTheme = 'auto'; // Replace localStorage with property
        this.init();
    }

    init() {
        const savedTheme = this.savedTheme || 'auto';
        const selector = document.getElementById('themeSelector');
        this.updateSystemTheme();
        this.mediaQuery.addEventListener('change', () => {
            this.updateSystemTheme();
            if (this.currentTheme === 'auto') this.applyTheme();
        });
        if (selector) {
            selector.value = savedTheme;
            selector.addEventListener('change', (e) => this.setTheme(e.target.value));
        }
        this.setTheme(savedTheme);
    }

    updateSystemTheme() {
        this.systemTheme = this.mediaQuery.matches ? 'dark' : 'light';
        this.updateUI();
    }

    setTheme(theme) {
        this.currentTheme = theme;
        this.savedTheme = theme; // Replace localStorage with property
        this.applyTheme();
        this.updateUI();
    }

    applyTheme() {
        const body = document.body;
        if (this.currentTheme === 'auto') {
            if (this.systemTheme === 'dark') body.removeAttribute('data-theme');
            else body.setAttribute('data-theme', 'light');
        } else {
            if (this.currentTheme === 'light') body.setAttribute('data-theme', 'light');
            else body.removeAttribute('data-theme');
        }
    }

    updateUI() {
        const currentThemeSpan = document.querySelector('#currentTheme');
        const activeTheme = document.querySelector('#activeTheme');
        const systemInfo = document.querySelector('#systemPreference');
        const statusIcon = document.querySelector('.theme-icon');
        
        if (!currentThemeSpan || !activeTheme || !systemInfo || !statusIcon) return;
        
        const themeIcons = { auto: '🌓', dark: '🌙', light: '☀️' };
        statusIcon.textContent = themeIcons[this.currentTheme];
        currentThemeSpan.textContent = this.currentTheme.charAt(0).toUpperCase() + this.currentTheme.slice(1);
        activeTheme.textContent = this.currentTheme === 'auto'
            ? `Auto (${this.systemTheme} mode active)`
            : this.currentTheme.charAt(0).toUpperCase() + this.currentTheme.slice(1);
        systemInfo.textContent = this.systemTheme.charAt(0).toUpperCase() + this.systemTheme.slice(1);
    }

    getEffectiveTheme() {
        return this.currentTheme === 'auto' ? this.systemTheme : this.currentTheme;
    }
}

// Initialize theme manager once
let themeManager;

document.addEventListener('DOMContentLoaded', function () {
    // Only create theme manager if it doesn't exist
    if (!themeManager) {
        themeManager = new ThemeManager();
        window.themeManager = themeManager;
    }

    // Table row interactions
    const tableRows = document.querySelectorAll('.data-table tbody tr');
    if (tableRows.length) {
        tableRows.forEach(row => {
            row.addEventListener('click', function () {
                tableRows.forEach(r => r.classList.remove('active'));
                this.classList.add('active');
            });
        });
        
        // Highlight active row function
        const highlightActiveRow = () => {
            const activeRow = document.querySelector('.data-table tbody tr.active');
            if (activeRow) activeRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        };
        
        // Initial highlight
        highlightActiveRow();
        
        // Add click listener to table
        const dataTable = document.querySelector('.data-table');
        if (dataTable) dataTable.addEventListener('click', highlightActiveRow);
    }

    // Query editor interactions
    const queryEditor = document.querySelector('.query-editor');
    if (queryEditor) {
        queryEditor.addEventListener('focus', function () {
            this.style.borderColor = 'var(--color-primary)';
        });
        queryEditor.addEventListener('blur', function () {
            this.style.borderColor = 'var(--color-table-border)';
        });
    }
});

// Expose theme manager globally for debugging
if (typeof window !== 'undefined') {
    window.addEventListener('load', () => {
        if (themeManager) {
            window.themeManager = themeManager;
        }
    });
}