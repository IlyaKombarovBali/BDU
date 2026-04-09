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