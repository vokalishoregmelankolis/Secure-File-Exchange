// VALORANT-STYLE JAVASCRIPT FOR SECURE VAULT SYSTEM

document.addEventListener('DOMContentLoaded', function() {
    
    // TACTICAL SOUND EFFECTS (Optional - can be enabled)
    function playTacticalSound() {
        // Placeholder for sound effects
        console.log('🔊 TACTICAL OPERATION CONFIRMED');
    }
    
    // GLITCH EFFECT FOR LOADING
    function createGlitchEffect(element) {
        element.style.animation = 'glitch 0.3s ease-in-out';
        setTimeout(() => {
            element.style.animation = '';
        }, 300);
    }
    
    // VALORANT-STYLE ALERT SYSTEM
    const alerts = document.querySelectorAll('.alert:not(.alert-warning):not(.alert-info)');
    alerts.forEach(alert => {
        // Add tactical styling
        alert.style.borderLeft = '4px solid var(--valorant-accent)';
        alert.style.fontFamily = '"Rajdhani", sans-serif';
        
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, 500);
        }, 5000);
    });
    
    // VALORANT-STYLE FILE INPUT
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'NO FILE SELECTED';
            const label = this.nextElementSibling;
            if (label && label.classList.contains('form-label')) {
                label.textContent = `📁 ${fileName.toUpperCase()}`;
                label.style.color = 'var(--valorant-accent)';
                createGlitchEffect(label);
                playTacticalSound();
            }
        });
    });
    
    // TACTICAL CONFIRMATION FOR DELETE OPERATIONS
    const deleteForms = document.querySelectorAll('form[action*="delete"]');
    deleteForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Custom Valorant-style confirm dialog
            const confirmed = confirm('⚠️ TACTICAL WARNING ⚠️\n\nCONFIRM FILE TERMINATION?\nThis intel will be permanently destroyed from the vault.\n\nOperation cannot be reversed.');
            
            if (confirmed) {
                playTacticalSound();
                this.submit();
            }
                e.preventDefault();
            }
        });
    });
    
    // Tooltip initialization
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Add loading spinner on form submit
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Processing...';
            }
        });
    });
    
    // Copy to clipboard functionality
    const copyButtons = document.querySelectorAll('.copy-to-clipboard');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.dataset.copy;
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalText = this.innerHTML;
                this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            });
        });
    });
    
    // Smooth scroll to top
    const scrollTopBtn = document.getElementById('scrollTop');
    if (scrollTopBtn) {
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 100) {
                scrollTopBtn.style.display = 'block';
            } else {
                scrollTopBtn.style.display = 'none';
            }
        });
        
        scrollTopBtn.addEventListener('click', function() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }
    
    // Table search functionality
    const searchInput = document.getElementById('tableSearch');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            const filter = this.value.toUpperCase();
            const table = document.querySelector('table tbody');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 0; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].textContent.toUpperCase().indexOf(filter) > -1) {
                        found = true;
                        break;
                    }
                }
                
                rows[i].style.display = found ? '' : 'none';
            }
        });
    }
    
});

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Format execution time
function formatExecutionTime(seconds) {
    if (seconds < 0.001) {
        return (seconds * 1000000).toFixed(2) + ' μs';
    } else if (seconds < 1) {
        return (seconds * 1000).toFixed(2) + ' ms';
    } else {
        return seconds.toFixed(4) + ' s';
    }
}

// Show loading overlay
function showLoading(message = 'Processing...') {
    const overlay = document.createElement('div');
    overlay.id = 'loadingOverlay';
    overlay.className = 'position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center';
    overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    overlay.style.zIndex = '9999';
    overlay.innerHTML = `
        <div class="text-center text-white">
            <div class="spinner-border" role="status" style="width: 3rem; height: 3rem;">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-3">${message}</p>
        </div>
    `;
    document.body.appendChild(overlay);
}

// Hide loading overlay
function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.remove();
    }
}