class ThemeManager {
    constructor() {
        this.currentTheme = 'auto';
        this.systemTheme = 'dark';
        this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

        this.init();
    }

    init() {
        // Load saved preference
        const savedTheme = localStorage.getItem('theme') || 'auto';

        // Set up system theme detection
        this.updateSystemTheme();
        this.mediaQuery.addEventListener('change', () => {
            this.updateSystemTheme();
            if (this.currentTheme === 'auto') {
                this.applyTheme();
            }
        });

        // Set up theme selector
        // const selector = document.getElementById('themeSelector');
        // selector.value = savedTheme;
        // selector.addEventListener('change', (e) => {
        //     this.setTheme(e.target.value);
        // });
        const selectors = document.querySelectorAll('#themeSelector');
        selectors.forEach(selector => {
            selector.value = savedTheme;
            selector.addEventListener('change', (e) => {
                this.setTheme(e.target.value);
            });
        });

        // Apply initial theme
        this.setTheme(savedTheme);
    }

    updateSystemTheme() {
        this.systemTheme = this.mediaQuery.matches ? 'dark' : 'light';
        this.updateUI();
    }

    setTheme(theme) {
        this.currentTheme = theme;
        localStorage.setItem('theme', theme);
        this.applyTheme();
        this.updateUI();
    }

    applyTheme() {
        const body = document.body;

        if (this.currentTheme === 'auto') {
            // Use system preference
            if (this.systemTheme === 'dark') {
                body.removeAttribute('data-theme');
            } else {
                body.setAttribute('data-theme', 'light');
            }
        } else {
            // Use explicit theme
            if (this.currentTheme === 'light') {
                body.setAttribute('data-theme', 'light');
            } else {
                body.removeAttribute('data-theme');
            }
        }
    }

    updateUI() {
        const themeStatus = document.querySelectorAll('#themeStatus');
        const currentThemeSpans = document.querySelectorAll('#currentTheme');
        const activeThemes = document.querySelectorAll('#activeTheme');
        const systemInfos = document.querySelectorAll('#systemPreference');

        // Update theme status
        const themeIcons = {
            auto: '🌓',
            dark: '🌙',
            light: '☀️'
        };

        const statusIcons = document.querySelectorAll('.theme-icon');
        statusIcons.forEach(statusIcon => {
            statusIcon.textContent = themeIcons[this.currentTheme];
        });
        currentThemeSpans.forEach(span => {
            span.textContent = this.currentTheme.charAt(0).toUpperCase() + this.currentTheme.slice(1);
        });
        
        // Update active theme info
        let activeText = '';
        if (this.currentTheme === 'auto') {
            activeText = `Auto (${this.systemTheme} mode active)`;
        } else {
            activeText = this.currentTheme.charAt(0).toUpperCase() + this.currentTheme.slice(1);
        }
        activeThemes.forEach(activeTheme => {
            activeTheme.textContent = activeText
        })

        // Update theme status
        themeStatus.forEach(status => {
            status.textContent = this.currentTheme.charAt(0).toUpperCase() + this.currentTheme.slice(1);
        });

        // Update system info
        systemInfos.forEach(systemInfo => {
            systemInfo.textContent = this.systemTheme.charAt(0).toUpperCase() + this.systemTheme.slice(1);
        });
    }

    getEffectiveTheme() {
        if (this.currentTheme === 'auto') {
            return this.systemTheme;
        }
        return this.currentTheme;
    }
}

// Initialize theme manager
const themeManager = new ThemeManager();

// Demo interactions
document.addEventListener('DOMContentLoaded', function () {
    // Add some interactive behavior to demo elements
    const tableRows = document.querySelectorAll('.data-table tbody tr');
    tableRows.forEach(row => {
        row.addEventListener('click', function () {
            tableRows.forEach(r => r.classList.remove('active'));
            this.classList.add('active');
        });
    });

    // Filter input interaction
    const filterInput = document.querySelector('.filter-input');
    filterInput.addEventListener('input', function () {
        console.log('Filtering:', this.value);
    });

    // Query editor interaction
    const queryEditor = document.querySelector('.query-editor');
    queryEditor.addEventListener('focus', function () {
        this.style.borderColor = 'var(--color-primary)';
    });
    queryEditor.addEventListener('blur', function () {
        this.style.borderColor = 'var(--color-table-border)';
    });
});

// Expose theme manager globally for debugging
window.themeManager = themeManager;