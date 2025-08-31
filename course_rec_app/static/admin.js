
let usageChart = null;

// Utility functions
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.className = `toast ${isError ? 'error' : 'success'}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    console.log("Admin dashboard initializing...");
    
    // Initialize dashboard
    initDashboard();
});

async function initDashboard() {
    // Check authentication
    const isAuthenticated = await checkAuth();
    if (!isAuthenticated) return;
    
    // Initialize UI components
    initUIComponents();
    
    // Load initial data
    loadInitialData();
    
    // Set up auto-refresh
    setupAutoRefresh();
}

async function checkAuth() {
    try {
        const response = await fetch('/api/admin/users', {
            method: 'GET',
            credentials: 'include'
        });

        if (response.status === 200) {
            return true;
        } else if (response.status === 401) {
            window.location.href = '/login';
            return false;
        } else {
            console.error('Unexpected response:', response.status);
            return false;
        }
    } catch (err) {
        console.error('Auth check failed:', err);
        return false;
    }
}

function initUIComponents() {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('sidebarToggle');
    const closeBtn = document.getElementById('sidebarClose'); 

    // Ensures correct initial state on mobile
    if (window.innerWidth < 768) {
        sidebar.classList.add('hidden');
    }

    toggleBtn?.addEventListener('click', () => {
        const isHidden = sidebar.classList.contains('hidden');
        sidebar.classList.toggle('hidden', !isHidden);
        sidebar.classList.toggle('show', isHidden);
    });

    closeBtn?.addEventListener('click', () => {
        sidebar.classList.remove('show');
        sidebar.classList.add('hidden');
    });

    // Closes sidebar when clicking outside (on mobile)
    window.addEventListener('click', (event) => {
        if (
            window.innerWidth < 768 &&
            sidebar.classList.contains('show') &&
            !sidebar.contains(event.target) &&
            !toggleBtn.contains(event.target)
        ) {
            sidebar.classList.remove('show');
            sidebar.classList.add('hidden');
        }
    });

    // Navigation
    initNavigation();
    
    // Modal controls
    initModals();
    
    // Form controls
    initFormControls();
    
    // Initialize weights UI
    initWeightsUI();
}

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.content-wrapper > div');
    const currentSectionText = document.getElementById('currentSection');
//sets dashboard as default active section
    document.getElementById('dashboard').classList.add('active');
    document.getElementById('dashboard').style.display = 'block';
    currentSectionText.textContent = 'Analytics';

    navItems.forEach(item => {
        item.addEventListener('click', function() {
            const sectionId = this.getAttribute('data-section');
            
            // Update active nav item
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            // Update current section text
            if (this.querySelector('span')) {
                currentSectionText.textContent = this.querySelector('span').textContent;
            }
            
            // Show target section
            contentSections.forEach(section => {
                section.classList.remove('active');
                section.style.display = 'none';
            });
            
            const targetSection = document.getElementById(sectionId);
            if (targetSection) {
                targetSection.classList.add('active');
                targetSection.style.display = 'block';
                
                // Load section-specific data
                switch(sectionId) {
                    case 'dashboard':
                        loadDashboardStats();
                        updateActivityLog();
                        break;
                    case 'users':
                        updateUserTable();
                        break;
                    case 'reports':
                        loadReportData();
                        break;
                    case 'system':
                        fetchSystemSettings();
                        break;
                    case 'questionnaire':
                        initWeightsUI();
                        break;
                }
            }
            
            // Hide sidebar on mobile
            if (window.innerWidth < 768) {
                sidebar.classList.add('hidden');
            }
        });
    });
}

function initModals() {
    // User modal
    document.getElementById('addUser')?.addEventListener('click', function(e) {
        e.preventDefault();
        window.editUserId = null;
        clearUserModal();
        showModal('userModal');
    });
    
    // Modal close handlers
    document.getElementById('cancelUser')?.addEventListener('click', () => hideModal('userModal'));
    document.getElementById('closeUserModal')?.addEventListener('click', () => hideModal('userModal'));
    document.getElementById('cancelReset')?.addEventListener('click', () => hideModal('passwordResetModal'));
    
    document.querySelectorAll('.close-btn, .modal-close').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const modal = this.closest('.modal-backdrop');
            if (modal) hideModal(modal.id);
        });
    });

    window.addEventListener('click', function(event) {
        document.querySelectorAll('.modal-backdrop').forEach(modal => {
            if (event.target === modal) hideModal(modal.id);
        });
    });
}

function initFormControls() {
    
    // Range inputs
    const rangeInputs = document.querySelectorAll('input[type="range"]');
    rangeInputs.forEach(input => {
        input.addEventListener('input', function() {
            if (this.id === 'matchThreshold') {
                document.getElementById('matchThresholdValue').textContent = this.value + '%';
            } else if (this.classList.contains('weight-slider')) {
                const valueDisplay = this.nextElementSibling;
                if (valueDisplay && valueDisplay.tagName === 'SPAN') {
                    valueDisplay.textContent = this.value + '%';
                }
                updateTotalWeights();
            }
        });
    });

    // Grade inputs
    const gradeInputs = document.querySelectorAll('.grade-value');
    gradeInputs.forEach(input => {
        input.addEventListener('input', function() {
            const value = parseFloat(this.value);
            if (isNaN(value) || value < 0 || value > 1) {
                this.classList.add('error-input');
            } else {
                this.classList.remove('error-input');
            }
        });
    });

    // Other buttons
    document.getElementById('resetGradeMapping')?.addEventListener('click', resetGradeMapping);
    
    // Export buttons
    document.getElementById('exportUsers')?.addEventListener('click', exportUsersToCSV);
    document.getElementById('exportStats')?.addEventListener('click', exportStatsToCSV);
    document.getElementById('exportLogs')?.addEventListener('click', exportActivityLog);
    
    // Filter panel
    document.getElementById('applyLogFilter')?.addEventListener('click', applyLogFilter);
    document.getElementById('clearLogFilter')?.addEventListener('click', clearLogFilter);
    document.getElementById('filterLog')?.addEventListener('click', toggleFilterPanel);
    
    // Refresh buttons
    document.getElementById('refreshStats')?.addEventListener('click', () => {
        loadDashboardStats();
        updateActivityLog();
    });
    document.getElementById('refreshReports')?.addEventListener('click', loadReportData);
    
    // System maintenance
    document.getElementById('backupSystem')?.addEventListener('click', createSystemBackup);
    document.getElementById('restoreSystem')?.addEventListener('click', initiateSystemRestore);
    
    // Save handlers
    document.getElementById('saveUser')?.addEventListener('click', saveUserHandler);
    document.getElementById('saveSettings')?.addEventListener('click', saveSettingsHandler);
    document.getElementById('saveWeights')?.addEventListener('click', saveWeightsHandler);
    document.getElementById('confirmReset')?.addEventListener('click', handlePasswordReset);

    // User filter panel
    document.getElementById('filterUser')?.addEventListener('click', toggleUserFilterPanel);
    document.getElementById('applyUserFilter')?.addEventListener('click', applyUserFilter);
    document.getElementById('clearUserFilter')?.addEventListener('click', clearUserFilter);

}

function loadInitialData() {
    // Load dashboard stats
    loadDashboardStats();
    updateActivityLog();
    
    // Initialize other data
    fetchSystemSettings();
    loadReportData();
}

function setupAutoRefresh() {
    // Token refresh every 5 minutes
    setInterval(refreshToken, 5 * 60 * 1000);
    
    // Auto-refresh dashboard every 5 minutes
    setInterval(() => {
        if (document.getElementById('dashboard')?.classList.contains('active')) {
            loadDashboardStats();
            updateActivityLog();
        }
    }, 5 * 60 * 1000);
}

// Modal functions
function showModal(modalId) {
    document.getElementById(modalId).style.display = 'flex';
}

function hideModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

function clearUserModal() {
    document.getElementById('firstName').value = '';
    document.getElementById('lastName').value = '';
    document.getElementById('username').value = '';
    document.getElementById('email').value = '';
    document.getElementById('password').value = '';
    document.getElementById('eduLevel').value = 'highSchool';
    document.getElementById('role').value = 'student';
    document.getElementById('usernameError').textContent = '';
    
    const sendVerification = document.getElementById('sendVerification');
    if (sendVerification) sendVerification.checked = false;
}

// User management
function updateUserTable(filters = {}) {
    showLoading();
    let url = '/api/admin/users';
    const params = new URLSearchParams(filters).toString();
    if (params) url += '?' + params;

    fetch(url, { credentials: 'include' })
    .then(response => response.json())
    .then(users => {
        const tbody = document.querySelector('#usersTable tbody');
        if (!tbody) return;

        tbody.innerHTML = users.map(user => `
            <tr data-user-id="${user.user_id}">
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td>${user.educationLevel}</td> <!-- Fixed property name -->
                <td>${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
                <td>${user.is_admin ? 'Admin' : 'User'}</td>
                <td class="${user.is_verified ? 'verified' : 'unverified'}">
                    ${user.is_verified ? 'Verified' : 'Unverified'}
                </td>
                <td>
                    <button class="action-btn edit-btn" title="Edit User"><i class="fas fa-edit"></i></button>
                    <button class="action-btn delete-btn" title="Delete User"><i class="fas fa-trash"></i></button>
                    <button class="action-btn reset-btn" title="Reset Password"><i class="fas fa-key"></i></button>
                </td>
            </tr>
        `).join('');

        bindUserActions();
    })
    .catch(err => {
        console.error('Failed to load users:', err);
        showToast('Failed to load users', true);
    })
    .finally(() => hideLoading());
}


function bindUserActions() {
    // Delete handler
    document.querySelectorAll('#usersTable .delete-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const tr = e.target.closest('tr');
            const userId = tr.dataset.userId;
            const username = tr.querySelector('td').textContent;
            
            if (!confirm(`Delete user ${username}?`)) return;
            
            showLoading();
            fetch(`/api/admin/users/${userId}`, { 
                method: 'DELETE',
                credentials: 'include'
            })
            .then(response => {
                if (!response.ok) throw new Error('Delete failed');
                showToast(`User ${username} deleted successfully`);
                updateUserTable();
            })
            .catch(err => {
                console.error('Delete failed:', err);
                showToast('Delete failed: ' + err.message, true);
            })
            .finally(() => hideLoading());
        });
    });
    
    // Reset password handler
    document.querySelectorAll('#usersTable .reset-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const tr = e.target.closest('tr');
            const userId = tr.dataset.userId;
            const username = tr.querySelector('td').textContent;
            
            if (!confirm(`Reset password for ${username}?`)) return;
            
            document.getElementById('resetUserId').value = userId;
            document.getElementById('resetUsername').textContent = username;
            showModal('passwordResetModal');
        });
    });

    // Edit handler
    document.querySelectorAll('#usersTable .edit-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const tr = e.target.closest('tr');
            const userId = tr.dataset.userId;
            
            showLoading();
            fetch(`/api/admin/users/${userId}`, {
                credentials: 'include'
            })
            .then(response => response.json())
            .then(user => {
                // Prefill modal fields
                document.getElementById('firstName').value = user.firstName || '';
                document.getElementById('lastName').value = user.lastName || '';
                document.getElementById('username').value = user.username || '';
                document.getElementById('email').value = user.email || '';
                document.getElementById('eduLevel').value = user.educationLevel || 'highSchool';
                document.getElementById('role').value = user.is_admin ? 'admin' : 'student';
                
                window.editUserId = userId;
                showModal('userModal');
            })
            .catch(err => {
                console.error('Failed to load user details:', err);
                showToast('Error loading user details', true);
            })
            .finally(() => hideLoading());
        });
    });
}

function toggleUserFilterPanel() {
    const panel = document.getElementById('userFilterPanel');
    panel.style.display = panel.style.display === 'block' ? 'none' : 'block';
}

function applyUserFilter() {
    const filters = {
        username: document.getElementById('filterUsername').value.trim(),
        email: document.getElementById('filterEmail').value.trim(),
        role: document.getElementById('filterRole').value,
        verified: document.getElementById('filterVerified').value
    };

    // Remove empty filters
    Object.keys(filters).forEach(key => {
        if (!filters[key]) delete filters[key];
    });
    
    updateUserTable(filters);
}

function clearUserFilter() {
  document.getElementById('filterUsername').value = '';
  document.getElementById('filterEmail').value = '';
  document.getElementById('filterRole').selectedIndex = 0;
  document.getElementById('filterVerified').selectedIndex = 0;
  updateUserTable();
}

async function saveUserHandler() {
    // Validates required fields
    const firstName = document.getElementById('firstName').value.trim();
    const lastName = document.getElementById('lastName').value.trim();
    const username = document.getElementById('username').value.trim();
    
    if (!firstName || !lastName || !username) {
        showToast('First name, last name and username are required', true);
        return;
    }
    
    // Check if username is available
    const isTaken = await isUsernameTaken(username, window.editUserId);
    if (isTaken) {
        document.getElementById('usernameError').textContent = 'Username is already taken';
        return;
    } else {
        document.getElementById('usernameError').textContent = '';
    }
    
    // Prepare user data
    const userData = {
        firstName,
        lastName,
        username,
        email: document.getElementById('email').value.trim(),
        educationLevel: document.getElementById('eduLevel').value,
        is_admin: document.getElementById('role').value === 'admin' ? 1 : 0,
        password: document.getElementById('password').value || null,
        sendVerification: document.getElementById('sendVerification')?.checked || false
    };
    
    const userId = window.editUserId;
    const method = userId ? 'PUT' : 'POST';
    const url = userId ? `/api/admin/users/${userId}` : '/api/admin/users';
    
    showLoading();
    fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(userData)
    })
    .then(response => {
        if (!response.ok) throw new Error('Save failed');
        return response.json();
    })
    .then(data => {
        showToast(userId ? 'User updated successfully' : 'User created successfully');
        updateUserTable();
        hideModal('userModal');
        window.editUserId = null;
    })
    .catch(error => {
        console.error('User save error:', error);
        showToast('Error saving user: ' + error.message, true);
    })
    .finally(() => hideLoading());
}

async function isUsernameTaken(username, userId = null) {
    try {
        const response = await fetch(`/api/admin/users/check-username?username=${username}${userId ? `&excludeId=${userId}` : ''}`, {
            credentials: 'include'
        });
        
        if (!response.ok) throw new Error('Validation failed');
        const result = await response.json();
        return result.isTaken;
    } catch (error) {
        console.error('Username validation error:', error);
        return true;
    }
}

// Activity Log
function updateActivityLog(dateFilter = null) {
    showLoading();
    let url = '/api/admin/activity-log';
    if (dateFilter) url += `?date=${dateFilter}`;

    fetch(url, { credentials: 'include' })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => {
                console.error('Activity log API error:', err);
                showToast(err.error || 'Failed to load activity log', true);
                return [];
            }).catch(() => {
                showToast('Failed to load activity log', true);
                return [];
            });
        }
        return response.json();
    })
    .then(data => {
        // Normalize to array
        let logs = [];
        if (Array.isArray(data)) {
            logs = data;
        } else if (data && typeof data === 'object') {
            logs = [data];
        } else {
            logs = [];
        }

        const tbody = document.querySelector('#activityLog tbody');
        if (!tbody) {
            console.error('#activityLog tbody not found');
            return;
        }
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4">No activity found</td></tr>';
        } else {
            tbody.innerHTML = logs.map(log => {
                // Parse timestamp safely
                let dateObj = new Date(log.timestamp);
                if (isNaN(dateObj)) {
                    dateObj = new Date(log.timestamp.replace(' ', 'T'));
                }
                const timeDisplay = isNaN(dateObj) ? log.timestamp : dateObj.toLocaleString();
                return `
                    <tr>
                        <td>${timeDisplay}</td>
                        <td>${log.username}</td>
                        <td>${log.action}</td>
                        <td>${log.target_type ? `${log.target_type} #${log.target_id}` : 'System'}</td>
                    </tr>`;
            }).join('');
        }
    })
    .catch(err => {
        console.error('Failed to load activity log:', err);
        showToast('Failed to load activity log', true);
    })
    .finally(() => hideLoading());
}


function toggleFilterPanel() {
    const panel = document.getElementById('logFilterPanel');
    panel.style.display = panel.style.display === 'none' ? 'inline-block' : 'none';
}

function applyLogFilter() {
    const date = document.getElementById('logDateFilter').value;
    updateActivityLog(date);
    document.getElementById('logFilterPanel').style.display = 'none';
}

function clearLogFilter() {
    document.getElementById('logDateFilter').value = '';
    updateActivityLog();
    document.getElementById('logFilterPanel').style.display = 'none';
}

// Dashboard stats
function loadDashboardStats() {
    showLoading();
    fetch('/api/admin/stats', { credentials: 'include' })
    .then(response => response.json())
    .then(stats => {
        document.getElementById('stats-users').textContent = stats.users?.toLocaleString() || '0';
        document.getElementById('stats-assessments').textContent = stats.assessments?.toLocaleString() || '0';
        document.getElementById('stats-courses').textContent = stats.courses?.toLocaleString() || '0';
        
        updateTrendElement('users', stats.users_trend);
        updateTrendElement('assessments', stats.assessments_trend);
    })
    .catch(err => {
        console.error('Stats load error:', err);
        showToast('Failed to load dashboard stats', true);
    })
    .finally(() => hideLoading());
}

function updateTrendElement(metric, trendValue) {
    const container = document.getElementById(`${metric}-trend`);
    if (!container || trendValue === null) return;
    
    container.innerHTML = '';
    
    const trendClass = trendValue >= 0 ? 'trend-up' : 'trend-down';
    const iconClass = trendValue >= 0 ? 'fas fa-arrow-up' : 'fas fa-arrow-down';
    const sign = trendValue >= 0 ? '+' : '-';
    
    container.innerHTML = `
        <span class="${trendClass}">
            <i class="${iconClass}"></i> ${sign}${Math.abs(trendValue)}%
        </span> since last month
    `;
}

// Reports
function loadReportData() {
    showLoading();
    
    // Load top courses
    fetch('/api/admin/reports/top-courses', { credentials: 'include' })
    .then(response => response.json())
    .then(courses => {
        const tbody = document.querySelector('#topCourses tbody');
        if (tbody) {
            tbody.innerHTML = courses.map(course => `
                <tr>
                    <td>${course.courseName}</td>
                    <td>${course.recommendations || 0}</td>
                    <td>${course.averageMatch ? course.averageMatch.toFixed(1) + '%' : 'N/A'}</td>
                </tr>
            `).join('');
        }
    })
    .catch(err => {
        console.error('Failed to load top courses:', err);
        showToast('Error loading top courses', true);
    });
    
    // Load usage chart data
    fetch('/api/admin/reports/usage-data', { credentials: 'include' })
    .then(response => response.json())
    .then(data => {
        renderUsageChart(data.registrations, data.assessments);
    })
    .catch(err => {
        console.error('Failed to load chart data:', err);
        showToast('Error loading usage data', true);
    })
    .finally(() => hideLoading());
}

function renderUsageChart(registrations = [], assessments = []) {
    const ctx = document.getElementById('usageChart');
    if (!ctx) return;
    
    // Destroy previous chart
    if (usageChart) usageChart.destroy();
    
    // Handle empty data
    if (registrations.length === 0 && assessments.length === 0) {
        ctx.innerHTML = `
            <div class="no-data-message">
                <i class="fas fa-chart-bar"></i>
                <p>No usage data available</p>
            </div>
        `;
        return;
    }
    
    // Prepare chart data
    const allDates = [...new Set([
        ...registrations.map(r => r.date),
        ...assessments.map(a => a.date)
    ])].sort();
    
    const registrationData = allDates.map(date => {
        const entry = registrations.find(r => r.date === date);
        return entry ? entry.count : 0;
    });
    
    const assessmentData = allDates.map(date => {
        const entry = assessments.find(a => a.date === date);
        return entry ? entry.count : 0;
    });
    
    const labels = allDates.map(date => {
        try {
            return new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        } catch {
            return date;
        }
    });
    
    // Create chart
    usageChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'User Registrations',
                    data: registrationData,
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Assessments Completed',
                    data: assessmentData,
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

// System settings
function fetchSystemSettings() {
    showLoading();
    fetch('/api/admin/settings', { credentials: 'include' })
    .then(response => response.json())
    .then(settings => {
        if (settings.matchThreshold) {
            document.getElementById('matchThreshold').value = settings.matchThreshold;
            document.getElementById('matchThresholdValue').textContent = settings.matchThreshold + '%';
        }
        
        if (settings.dataRetentionDays !== undefined) {
            document.getElementById('dataRetention').value = settings.dataRetentionDays;
            document.getElementById('dataRetentionValue').textContent = 
                settings.dataRetentionDays === 30 ? '30 days' :
                settings.dataRetentionDays === 90 ? '90 days' :
                settings.dataRetentionDays === 365 ? '1 year' : 'Indefinitely';
        }
        
        if (settings.gradeMapping) {
            initGradeMappingUI(settings.gradeMapping);
        }
    })
    .catch(err => {
        console.error('Failed to load system settings:', err);
        showToast('Failed to load system settings', true);
    })
    .finally(() => hideLoading());
}

function initGradeMappingUI(gradeMapping) {
    document.querySelectorAll('.grade-value').forEach(input => {
        const grade = input.dataset.grade;
        if (gradeMapping[grade] !== undefined) {
            input.value = gradeMapping[grade];
        }
    });
}

function resetGradeMapping() {
    const defaultGrades = {
        'A': 1.0, 'A-': 0.9, 'B+': 0.8, 'B': 0.7, 'B-': 0.6,
        'C+': 0.5, 'C': 0.4, 'C-': 0.3, 'D+': 0.2,
        'D': 0.1, 'D-': 0.0, 'E': 0.0
    };
    
    document.querySelectorAll('.grade-value').forEach(input => {
        const grade = input.dataset.grade;
        if (defaultGrades[grade] !== undefined) {
            input.value = defaultGrades[grade];
        }
    });
    showToast("Grade mapping reset to default.");
}

function saveSettingsHandler() {
    // Validate grade values
    let isValid = true;
    document.querySelectorAll('.grade-value').forEach(input => {
        const value = parseFloat(input.value);
        if (isNaN(value) || value < 0 || value > 1) {
            input.classList.add('error-input');
            isValid = false;
        } else {
            input.classList.remove('error-input');
        }
    });

    if (!isValid) {
        showToast('Grade values must be between 0.0 and 1.0!', true);
        return;
    }

    // Prepare payload
    const gradeMapping = {};
    document.querySelectorAll('.grade-value').forEach(input => {
        gradeMapping[input.dataset.grade] = parseFloat(input.value);
    });

    const payload = {
        matchThreshold: parseInt(document.getElementById('matchThreshold').value),
        dataRetentionDays: parseInt(document.getElementById('dataRetention').value),
        gradeMapping
    };

    showLoading();
    fetch('/api/admin/settings', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) throw new Error('Save failed');
        showToast('Settings saved successfully!');
    })
    .catch(error => {
        console.error('Error saving settings:', error);
        showToast('Error saving settings: ' + error.message, true);
    })
    .finally(() => hideLoading());
}

// Questionnaire weights
function initWeightsUI() {
    showLoading();
    fetch('/api/admin/weights', { credentials: 'include' })
        .then(response => response.json())
        .then(weights => {
            // Convert decimal to percentage
            document.getElementById('interestWeight').value = Math.round(weights.interests * 100);
            document.getElementById('learningWeight').value = Math.round(weights.learning_preferences * 100);
            document.getElementById('academicWeight').value = Math.round(weights.required_subjects * 100);
            document.getElementById('personalityWeight').value = Math.round(weights.personality_traits * 100);
            document.getElementById('careerGoalsWeight').value = Math.round(weights.career_goals * 100);
            
            // Update display values
            document.querySelectorAll('.weight-sliders input[type="range"]').forEach(slider => {
                slider.nextElementSibling.textContent = slider.value + '%';
            });
            
            updateTotalWeights();
        })
    .catch(err => {
        console.error('Failed to load weights:', err);
        showToast('Failed to load weights', true);
    })
    .finally(() => hideLoading());
}

function updateTotalWeights() {
    const weights = [
        parseInt(document.getElementById('interestWeight').value) || 0,
        parseInt(document.getElementById('learningWeight').value) || 0,
        parseInt(document.getElementById('academicWeight').value) || 0,
        parseInt(document.getElementById('personalityWeight').value) || 0,
        parseInt(document.getElementById('careerGoalsWeight').value) || 0
    ];

    const total = weights.reduce((sum, weight) => sum + weight, 0);
    const totalDisplay = document.getElementById('weightTotalDisplay');
    
    if (totalDisplay) {
        totalDisplay.textContent = `Total: ${total}%`;
        totalDisplay.style.color = (total === 100 ? 'green' : 'red');
    }
    
    return total;
}


function saveWeightsHandler() {
    const total = updateTotalWeights();
    if (total !== 100) {
        showToast('Weights must total 100%', true);
        return;
    }

    showLoading();
    const payload = {
        required_subjects: parseInt(document.getElementById('academicWeight').value) / 100,
        interests: parseInt(document.getElementById('interestWeight').value) / 100,
        learning_preferences: parseInt(document.getElementById('learningWeight').value) / 100,
        personality_traits: parseInt(document.getElementById('personalityWeight').value) / 100,
        career_goals: parseInt(document.getElementById('careerGoalsWeight').value) / 100
    };

    fetch('/api/admin/weights', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) throw new Error('Save failed');
        showToast('Weights saved successfully!');
    })
    .catch(error => {
        console.error('Error saving weights:', error);
        showToast('Error saving weights: ' + error.message, true);
    })
    .finally(() => hideLoading());
}

// Export functions
function exportActivityLog() {
    showLoading();
    fetch('/api/admin/activity-log/export', { credentials: 'include' })
    .then(response => response.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `activity_log_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast('Activity log exported successfully');
    })
    .catch(err => {
        console.error('Export failed:', err);
        showToast('Export failed: ' + err.message, true);
    })
    .finally(() => hideLoading());
}

function exportUsersToCSV() {
    showLoading();
    fetch('/api/admin/users/export', { credentials: 'include' })
    .then(response => response.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'users_export.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast('Users exported successfully');
    })
    .catch(err => {
        console.error('Export failed:', err);
        showToast('Export failed: ' + err.message, true);
    })
    .finally(() => hideLoading());
}

function exportStatsToCSV() {
    showLoading();
    fetch('/api/admin/reports/export', { credentials: 'include' })
    .then(response => response.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'report_export.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast('Reports exported successfully');
    })
    .catch(err => {
        console.error('Export failed:', err);
        showToast('Export failed: ' + err.message, true);
    })
    .finally(() => hideLoading());
}

// System maintenance
function createSystemBackup() {
    if (!confirm('Create a system backup? This may take several minutes.')) return;
    
    showLoading();
    fetch('/api/admin/system/backup', { 
        method: 'POST',
        credentials: 'include'
    })
    .then(response => response.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `courseadvisor_backup_${new Date().toISOString().split('T')[0]}.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast('Backup created successfully!');
    })
    .catch(error => {
        console.error('Backup error:', error);
        showToast('Backup failed: ' + error.message, true);
    })
    .finally(() => hideLoading());
}

function initiateSystemRestore() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.zip';
    
    input.onchange = function(e) {
        const file = e.target.files[0];
        if (!file) return;
        
        if (!confirm('WARNING: Restoring from backup will overwrite all current data. Continue?')) {
            return;
        }
        
        showLoading();
        const formData = new FormData();
        formData.append('backup', file);
        
        fetch('/api/admin/system/restore', {
            method: 'POST',
            credentials: 'include',
            body: formData
        })
        .then(response => {
            if (!response.ok) throw new Error('Restore failed');
            return response.json();
        })
        .then(data => {
            showToast(data.message);
            setTimeout(() => location.reload(), 3000);
        })
        .catch(error => {
            console.error('Restore error:', error);
            showToast('Restore failed: ' + error.message, true);
        })
        .finally(() => hideLoading());
    };
    
    input.click();
}

// Password reset
function handlePasswordReset() {
    const userId = document.getElementById('resetUserId').value;
    const adminPassword = document.getElementById('adminPassword').value;
    
    if (!adminPassword) {
        showToast('Please enter your admin password', true);
        return;
    }
    
    showLoading();
    fetch(`/api/admin/users/${userId}/reset-password`, {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ adminPassword })
    })
    .then(response => {
        if (!response.ok) throw new Error('Password reset failed');
        showToast('Password reset successfully!');
        hideModal('passwordResetModal');
    })
    .catch(error => {
        console.error('Password reset error:', error);
        showToast('Reset failed: ' + error.message, true);
    })
    .finally(() => hideLoading());
}

// Token refresh
function refreshToken() {
    fetch('/refresh', {
        method: 'POST',
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        if (data.token) {
            document.cookie = `auth_token=${data.token}; path=/; max-age=18000; secure; HttpOnly; samesite=strict`;
        }
    })
    .catch(err => console.error('Token refresh failed:', err));
}