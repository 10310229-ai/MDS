// Admin Dashboard JavaScript

// API Configuration
const API_BASE_URL = window.location.origin;

// Utility function for API calls
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

// Load dashboard stats
async function loadDashboardStats() {
    try {
        const stats = await apiCall('/api/stats');
        
        // Update stat values
        document.querySelectorAll('.stat-value').forEach((el, index) => {
            const statData = [
                { value: stats.totalOrders?.toLocaleString() || '0', change: stats.ordersGrowth || 0 },
                { value: `GHS ${stats.totalRevenue?.toLocaleString() || '0'}`, change: stats.revenueGrowth || 0 },
                { value: stats.totalCustomers?.toLocaleString() || '0', change: stats.customersGrowth || 0 },
                { value: `${stats.successRate || 0}%`, change: stats.successRateChange || 0 }
            ];
            
            if (statData[index]) {
                el.textContent = statData[index].value;
                
                // Update change indicator
                const changeEl = el.closest('.stat-card-admin').querySelector('.stat-change');
                if (changeEl) {
                    const change = statData[index].change;
                    changeEl.innerHTML = `<i class="fas fa-arrow-${change >= 0 ? 'up' : 'down'}"></i> ${Math.abs(change)}%`;
                    changeEl.className = `stat-change ${change >= 0 ? 'positive' : 'negative'}`;
                }
            }
        });
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Load recent orders
async function loadRecentOrders() {
    try {
        const response = await apiCall('/api/orders?limit=5');
        const orders = response.orders || [];
        
        const tbody = document.querySelector('#dashboard .admin-table tbody');
        if (!tbody) return;
        
        tbody.innerHTML = orders.map(order => `
            <tr>
                <td>${order.id}</td>
                <td>${order.customer}</td>
                <td>${order.package}</td>
                <td>GHS ${order.amount.toFixed(2)}</td>
                <td><span class="status-badge ${order.status}">${order.status.charAt(0).toUpperCase() + order.status.slice(1)}</span></td>
                <td><button class="action-btn" onclick="viewOrder('${order.id}')"><i class="fas fa-eye"></i></button></td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to load recent orders:', error);
    }
}

// Load all orders for orders page
async function loadAllOrders(filters = {}) {
    try {
        const params = new URLSearchParams({
            page: filters.page || 1,
            limit: filters.limit || 10,
            ...(filters.status && { status: filters.status }),
            ...(filters.network && { network: filters.network }),
            ...(filters.search && { search: filters.search })
        });
        
        const response = await apiCall(`/api/orders?${params}`);
        const orders = response.orders || [];
        
        const tbody = document.querySelector('#orders .admin-table tbody');
        if (!tbody) return;
        
        tbody.innerHTML = orders.map(order => {
            const date = new Date(order.date).toLocaleDateString('en-GB', { 
                day: 'numeric', 
                month: 'short', 
                year: 'numeric' 
            });
            
            return `
                <tr>
                    <td><input type="checkbox" data-order-id="${order.id}"></td>
                    <td>${order.id}</td>
                    <td>${date}</td>
                    <td>${order.customer}</td>
                    <td>${order.phone}</td>
                    <td>${order.package}</td>
                    <td>GHS ${order.amount.toFixed(2)}</td>
                    <td><span class="status-badge ${order.status}">${order.status.charAt(0).toUpperCase() + order.status.slice(1)}</span></td>
                    <td>
                        <button class="action-btn" onclick="viewOrder('${order.id}')"><i class="fas fa-eye"></i></button>
                        <button class="action-btn" onclick="editOrder('${order.id}')"><i class="fas fa-edit"></i></button>
                        <button class="action-btn danger" onclick="deleteOrder('${order.id}')"><i class="fas fa-trash"></i></button>
                    </td>
                </tr>
            `;
        }).join('');
        
        // Update pagination
        updatePagination(response.page, response.totalPages, response.total);
    } catch (error) {
        console.error('Failed to load orders:', error);
    }
}

// Update pagination display
function updatePagination(currentPage, totalPages, totalItems) {
    const paginationInfo = document.querySelector('.pagination-info');
    const paginationControls = document.querySelector('.pagination-controls');
    
    if (paginationInfo) {
        const start = ((currentPage - 1) * 10) + 1;
        const end = Math.min(currentPage * 10, totalItems);
        paginationInfo.textContent = `Showing ${start}-${end} of ${totalItems} orders`;
    }
    
    if (paginationControls) {
        let html = `<button class="pagination-btn" onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}><i class="fas fa-chevron-left"></i></button>`;
        
        for (let i = 1; i <= Math.min(5, totalPages); i++) {
            html += `<button class="pagination-btn ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</button>`;
        }
        
        if (totalPages > 5) {
            html += `<button class="pagination-btn">...</button>`;
            html += `<button class="pagination-btn" onclick="changePage(${totalPages})">${totalPages}</button>`;
        }
        
        html += `<button class="pagination-btn" onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}><i class="fas fa-chevron-right"></i></button>`;
        
        paginationControls.innerHTML = html;
    }
}

// Load top packages
async function loadTopPackages() {
    try {
        const packages = await apiCall('/api/packages/top');
        
        const packageList = document.querySelector('.package-list');
        if (!packageList) return;
        
        packageList.innerHTML = packages.map(pkg => {
            const networkClass = pkg.network.toLowerCase().replace(/\s+/g, '');
            return `
                <div class="package-item">
                    <div class="package-info">
                        <div class="package-icon ${networkClass}">
                            <i class="fas fa-mobile-alt"></i>
                        </div>
                        <div class="package-details">
                            <div class="package-name">${pkg.name}</div>
                            <div class="package-sales">${pkg.sales} sales</div>
                        </div>
                    </div>
                    <div class="package-amount">GHS ${pkg.revenue.toLocaleString()}</div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load top packages:', error);
    }
}

// View order details
async function viewOrder(orderId) {
    try {
        const order = await apiCall(`/api/orders/${orderId}`);
        alert(`Order Details:\n\nID: ${order.id}\nCustomer: ${order.customer}\nPackage: ${order.package}\nAmount: GHS ${order.amount}\nStatus: ${order.status}`);
        // You can replace this with a modal
    } catch (error) {
        console.error('Failed to load order:', error);
        alert('Failed to load order details');
    }
}

// Edit order
async function editOrder(orderId) {
    const newStatus = prompt('Enter new status (pending/processing/completed/cancelled):');
    if (!newStatus) return;
    
    try {
        await apiCall(`/api/orders/${orderId}`, {
            method: 'PUT',
            body: JSON.stringify({ status: newStatus.toLowerCase() })
        });
        alert('Order updated successfully');
        loadAllOrders();
    } catch (error) {
        console.error('Failed to update order:', error);
        alert('Failed to update order');
    }
}

// Delete order
async function deleteOrder(orderId) {
    if (!confirm('Are you sure you want to delete this order?')) return;
    
    try {
        await apiCall(`/api/orders/${orderId}`, { method: 'DELETE' });
        alert('Order deleted successfully');
        loadAllOrders();
    } catch (error) {
        console.error('Failed to delete order:', error);
        alert('Failed to delete order');
    }
}

// Change page
let currentFilters = {};
function changePage(page) {
    currentFilters.page = page;
    loadAllOrders(currentFilters);
}

// Export functions to global scope
window.viewOrder = viewOrder;
window.editOrder = editOrder;
window.deleteOrder = deleteOrder;
window.changePage = changePage;

document.addEventListener('DOMContentLoaded', function() {
    // Sidebar Navigation
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.admin-section');
    const pageTitle = document.querySelector('.page-title');

    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all nav items
            navItems.forEach(nav => nav.classList.remove('active'));
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Hide all sections
            sections.forEach(section => section.classList.remove('active'));
            
            // Show selected section
            const sectionId = this.getAttribute('data-section');
            const targetSection = document.getElementById(sectionId);
            if (targetSection) {
                targetSection.classList.add('active');
                
                // Update page title
                const sectionName = this.querySelector('span').textContent;
                pageTitle.textContent = sectionName;
            }
        });
    });

    // Mobile Sidebar Toggle with backdrop + scroll lock
    const mobileSidebarToggle = document.getElementById('mobileSidebarToggle');
    const sidebar = document.getElementById('adminSidebar');
    let sidebarBackdrop = null;

    const isMobile = () => window.innerWidth <= 768;

    function createSidebarBackdrop(){
        if (sidebarBackdrop) return sidebarBackdrop;
        sidebarBackdrop = document.createElement('div');
        sidebarBackdrop.className = 'sidebar-backdrop';
        document.body.appendChild(sidebarBackdrop);
        requestAnimationFrame(()=> sidebarBackdrop.classList.add('show'));
        sidebarBackdrop.addEventListener('click', closeSidebar);
        return sidebarBackdrop;
    }

    function removeSidebarBackdrop(){
        if (!sidebarBackdrop) return;
        sidebarBackdrop.classList.remove('show');
        setTimeout(()=>{ sidebarBackdrop?.remove(); sidebarBackdrop = null; }, 200);
    }

    function setToggleIcon(opened){
        if (!mobileSidebarToggle) return;
        const icon = mobileSidebarToggle.querySelector('i');
        if (!icon) return;
        icon.classList.toggle('fa-bars', !opened);
        icon.classList.toggle('fa-times', opened);
    }

    function openSidebar(){
        if (!sidebar) return;
        sidebar.classList.add('open');
        document.body.classList.add('no-scroll');
        createSidebarBackdrop();
        setToggleIcon(true);
    }

    function closeSidebar(){
        if (!sidebar) return;
        sidebar.classList.remove('open');
        document.body.classList.remove('no-scroll');
        removeSidebarBackdrop();
        setToggleIcon(false);
    }

    if (mobileSidebarToggle) {
        mobileSidebarToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const opened = sidebar?.classList.contains('open');
            if (opened) closeSidebar(); else openSidebar();
        });
    }

    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', function(e) {
        if (!isMobile() || !sidebar || !mobileSidebarToggle) return;
        if (!sidebar.classList.contains('open')) return;
        if (!sidebar.contains(e.target) && !mobileSidebarToggle.contains(e.target)) {
            closeSidebar();
        }
    });

    // Close with ESC key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && sidebar?.classList.contains('open')) closeSidebar();
    });

    // Auto-reset when resizing back to desktop widths
    window.addEventListener('resize', () => {
        if (!isMobile()) closeSidebar();
    });

    // Table row selection
    const tableCheckboxes = document.querySelectorAll('.admin-table input[type="checkbox"]');
    tableCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const row = this.closest('tr');
            if (this.checked) {
                row.style.background = 'rgba(14,165,255,0.08)';
            } else {
                row.style.background = '';
            }
        });
    });

    // Action button handlers
    const actionButtons = document.querySelectorAll('.action-btn');
    actionButtons.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const icon = this.querySelector('i');
            
            if (icon.classList.contains('fa-eye')) {
                console.log('View details');
                // Add view functionality
            } else if (icon.classList.contains('fa-edit')) {
                console.log('Edit item');
                // Add edit functionality
            } else if (icon.classList.contains('fa-trash')) {
                if (confirm('Are you sure you want to delete this item?')) {
                    console.log('Delete item');
                    // Add delete functionality
                }
            }
        });
    });

    // Filter select handlers
    const filterSelects = document.querySelectorAll('.filter-select');
    filterSelects.forEach(select => {
        select.addEventListener('change', function() {
            const filterType = this.options[0].text.includes('Status') ? 'status' : 'network';
            currentFilters[filterType] = this.value;
            currentFilters.page = 1; // Reset to first page
            loadAllOrders(currentFilters);
        });
    });

    // Search functionality
    const searchInput = document.querySelector('.filter-input');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                currentFilters.search = this.value;
                currentFilters.page = 1; // Reset to first page
                loadAllOrders(currentFilters);
            }, 300);
        });
    }

    // Load initial data for dashboard
    loadDashboardStats();
    loadRecentOrders();
    loadTopPackages();

    // When orders section is opened, load all orders
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            const sectionId = this.getAttribute('data-section');
            if (sectionId === 'orders') {
                loadAllOrders(currentFilters);
            }
        });
    });

    // Pagination
    const paginationBtns = document.querySelectorAll('.pagination-btn');
    paginationBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            if (!this.disabled && !this.classList.contains('active')) {
                paginationBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
            }
        });
    });

    // Animate stats on page load
    const statValues = document.querySelectorAll('.stat-value');
    statValues.forEach(stat => {
        stat.style.opacity = '0';
        setTimeout(() => {
            stat.style.transition = 'opacity 0.5s ease';
            stat.style.opacity = '1';
        }, 100);
    });

    // Settings Page Functionality
    initializeSettings();

    console.log('Admin dashboard initialized with live data');
});

// Settings Functions
function initializeSettings() {
    // Load settings from localStorage
    loadSettings();
    
    // General Settings Form
    const generalForm = document.getElementById('generalSettingsForm');
    if (generalForm) {
        generalForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const settings = Object.fromEntries(formData);
            saveSettings('general', settings);
            showToast('General settings saved successfully!', 'success');
        });
    }
    
    // Payment Settings Form
    const paymentForm = document.getElementById('paymentSettingsForm');
    if (paymentForm) {
        paymentForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const settings = Object.fromEntries(formData);
            saveSettings('payment', settings);
            showToast('Payment settings saved successfully!', 'success');
        });
    }
    
    // Notification Settings Form
    const notificationForm = document.getElementById('notificationSettingsForm');
    if (notificationForm) {
        notificationForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const settings = {};
            formData.forEach((value, key) => {
                settings[key] = this.querySelector(`[name="${key}"]`).type === 'checkbox' 
                    ? this.querySelector(`[name="${key}"]`).checked 
                    : value;
            });
            saveSettings('notifications', settings);
            showToast('Notification settings saved successfully!', 'success');
        });
    }
    
    // Business Hours Form
    const businessHoursForm = document.getElementById('businessHoursForm');
    const customHoursDiv = document.getElementById('customHours');
    const operation24_7 = document.querySelector('[name="24_7_operation"]');
    
    if (operation24_7) {
        operation24_7.addEventListener('change', function() {
            customHoursDiv.style.display = this.checked ? 'none' : 'block';
        });
    }
    
    if (businessHoursForm) {
        businessHoursForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const settings = Object.fromEntries(formData);
            settings['24_7_operation'] = operation24_7.checked;
            saveSettings('businessHours', settings);
            showToast('Business hours saved successfully!', 'success');
        });
    }
    
    // Security Settings Form
    const securityForm = document.getElementById('securitySettingsForm');
    if (securityForm) {
        securityForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (newPassword && newPassword !== confirmPassword) {
                showToast('Passwords do not match!', 'error');
                return;
            }
            
            if (newPassword && newPassword.length < 8) {
                showToast('Password must be at least 8 characters!', 'error');
                return;
            }
            
            const twoFactorAuth = this.querySelector('[name="twoFactorAuth"]').checked;
            saveSettings('security', { 
                passwordChanged: !!newPassword,
                twoFactorAuth: twoFactorAuth,
                lastPasswordChange: new Date().toISOString()
            });
            showToast('Security settings updated successfully!', 'success');
            this.reset();
        });
    }
    
    // Maintenance Mode Form
    const maintenanceForm = document.getElementById('maintenanceForm');
    if (maintenanceForm) {
        maintenanceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const maintenanceMode = document.getElementById('maintenanceMode').checked;
            const maintenanceMessage = document.getElementById('maintenanceMessage').value;
            
            saveSettings('maintenance', {
                enabled: maintenanceMode,
                message: maintenanceMessage
            });
            
            if (maintenanceMode) {
                showToast('Maintenance mode enabled!', 'success');
            } else {
                showToast('Maintenance mode disabled!', 'success');
            }
        });
    }
    
    // Backup Now Button
    const backupBtn = document.getElementById('backupNowBtn');
    if (backupBtn) {
        backupBtn.addEventListener('click', function() {
            this.disabled = true;
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Backing up...';
            
            // Simulate backup process
            setTimeout(() => {
                const now = new Date().toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true
                });
                document.getElementById('lastBackup').textContent = now;
                localStorage.setItem('lastBackup', now);
                
                this.disabled = false;
                this.innerHTML = '<i class="fas fa-database"></i> Backup Now';
                showToast('Backup completed successfully!', 'success');
            }, 2000);
        });
    }
    
    // Clear Cache Button
    const clearCacheBtn = document.getElementById('clearCacheBtn');
    if (clearCacheBtn) {
        clearCacheBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to clear the cache?')) {
                // Clear specific cache items (not settings)
                const keysToKeep = ['adminSettings', 'lastBackup'];
                const allKeys = Object.keys(localStorage);
                allKeys.forEach(key => {
                    if (!keysToKeep.includes(key)) {
                        localStorage.removeItem(key);
                    }
                });
                showToast('Cache cleared successfully!', 'success');
            }
        });
    }
    
    // Export Data Button
    const exportDataBtn = document.getElementById('exportDataBtn');
    if (exportDataBtn) {
        exportDataBtn.addEventListener('click', async function() {
            try {
                const response = await apiCall('/api/orders?limit=10000');
                const data = {
                    orders: response.orders,
                    exportDate: new Date().toISOString(),
                    totalOrders: response.total
                };
                
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `motion-data-export-${new Date().toISOString().split('T')[0]}.json`;
                a.click();
                window.URL.revokeObjectURL(url);
                
                showToast('Data exported successfully!', 'success');
            } catch (error) {
                showToast('Failed to export data!', 'error');
            }
        });
    }
    
    // Add Package Button
    const addPackageBtn = document.getElementById('addPackageBtn');
    if (addPackageBtn) {
        addPackageBtn.addEventListener('click', function() {
            showPackageModal();
        });
    }
    
    // Load packages in settings
    loadPackagesInSettings();
}

function saveSettings(category, settings) {
    const allSettings = JSON.parse(localStorage.getItem('adminSettings') || '{}');
    allSettings[category] = settings;
    localStorage.setItem('adminSettings', JSON.stringify(allSettings));
}

function loadSettings() {
    const allSettings = JSON.parse(localStorage.getItem('adminSettings') || '{}');
    
    // Load general settings
    if (allSettings.general) {
        Object.keys(allSettings.general).forEach(key => {
            const input = document.querySelector(`[name="${key}"]`);
            if (input) input.value = allSettings.general[key];
        });
    }
    
    // Load payment settings
    if (allSettings.payment) {
        Object.keys(allSettings.payment).forEach(key => {
            const input = document.querySelector(`[name="${key}"]`);
            if (input) {
                if (input.type === 'checkbox') {
                    input.checked = allSettings.payment[key] === 'on';
                } else {
                    input.value = allSettings.payment[key];
                }
            }
        });
    }
    
    // Load notification settings
    if (allSettings.notifications) {
        Object.keys(allSettings.notifications).forEach(key => {
            const input = document.querySelector(`[name="${key}"]`);
            if (input) {
                if (input.type === 'checkbox') {
                    input.checked = allSettings.notifications[key];
                } else {
                    input.value = allSettings.notifications[key];
                }
            }
        });
    }
    
    // Load maintenance settings
    if (allSettings.maintenance) {
        const maintenanceMode = document.getElementById('maintenanceMode');
        const maintenanceMessage = document.getElementById('maintenanceMessage');
        if (maintenanceMode) maintenanceMode.checked = allSettings.maintenance.enabled;
        if (maintenanceMessage) maintenanceMessage.value = allSettings.maintenance.message;
    }
    
    // Load last backup time
    const lastBackup = localStorage.getItem('lastBackup');
    if (lastBackup) {
        const lastBackupEl = document.getElementById('lastBackup');
        if (lastBackupEl) lastBackupEl.textContent = lastBackup;
    }
}

async function loadPackagesInSettings() {
    try {
        const packages = await apiCall('/api/packages');
        const packagesList = document.querySelector('.packages-list');
        if (!packagesList) return;
        
        packagesList.innerHTML = packages.map(pkg => `
            <div class="package-settings-item">
                <div class="package-settings-info">
                    <div class="package-icon ${pkg.network.toLowerCase()}">
                        <i class="fas fa-mobile-alt"></i>
                    </div>
                    <div class="package-settings-details">
                        <h4>${pkg.name}</h4>
                        <p>${pkg.data} - GHS ${pkg.price} - ${pkg.validity}</p>
                    </div>
                </div>
                <div class="package-settings-actions">
                    <button class="btn-admin secondary" onclick="editPackage('${pkg.id}')">
                        <i class="fas fa-edit"></i> Edit
                    </button>
                    <button class="btn-admin secondary" onclick="togglePackage('${pkg.id}', ${pkg.active})">
                        <i class="fas fa-${pkg.active ? 'eye-slash' : 'eye'}"></i> ${pkg.active ? 'Disable' : 'Enable'}
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load packages:', error);
    }
}

function showPackageModal() {
    const name = prompt('Package Name (e.g., MTN 10GB):');
    if (!name) return;
    
    const network = prompt('Network (MTN/Telecel/AirtelTigo):');
    if (!network) return;
    
    const data = prompt('Data Amount (e.g., 10GB):');
    if (!data) return;
    
    const price = prompt('Price (GHS):');
    if (!price) return;
    
    showToast('Package added successfully!', 'success');
    // In a real implementation, this would call API to add package
}

function editPackage(packageId) {
    showToast('Edit package: ' + packageId, 'success');
    // Implement edit functionality
}

function togglePackage(packageId, currentStatus) {
    const newStatus = !currentStatus;
    showToast(`Package ${newStatus ? 'enabled' : 'disabled'} successfully!`, 'success');
    loadPackagesInSettings();
    // Implement toggle functionality
}

function showToast(message, type = 'success') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast-message');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create new toast
    const toast = document.createElement('div');
    toast.className = `toast-message ${type}`;
    toast.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(toast);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Export functions to global scope
window.editPackage = editPackage;
window.togglePackage = togglePackage;
