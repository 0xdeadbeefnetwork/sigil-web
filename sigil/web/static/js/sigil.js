        function copyToClipboard(text, btn) {
            navigator.clipboard.writeText(text).then(function() {
                if (btn) {
                    var original = btn.textContent;
                    btn.textContent = 'Copied!';
                    btn.style.borderColor = '#00ff41';
                    setTimeout(function() {
                        btn.textContent = original;
                        btn.style.borderColor = '';
                    }, 2000);
                }
            }).catch(function() {
                // Fallback for older browsers
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                if (btn) {
                    var original = btn.textContent;
                    btn.textContent = 'Copied!';
                    setTimeout(function() { btn.textContent = original; }, 2000);
                }
            });
        }

        function setLoading(btn, loadingText) {
            if (!btn) return;
            btn._originalText = btn.textContent;
            btn.textContent = loadingText || 'Processing...';
            btn.classList.add('btn-loading');
            btn.disabled = true;
        }

        function clearLoading(btn) {
            if (!btn || !btn._originalText) return;
            btn.textContent = btn._originalText;
            btn.classList.remove('btn-loading');
            btn.disabled = false;
        }

        // Auto-attach loading states to forms with data-loading attribute
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('form[data-loading]').forEach(function(form) {
                form.addEventListener('submit', function() {
                    var btn = form.querySelector('button[type="submit"]');
                    if (btn) {
                        setLoading(btn, form.getAttribute('data-loading'));
                    }
                });
            });
        });
