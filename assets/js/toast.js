// Very small toast utility
function showToast(message, timeout = 3500) {
    const t = document.createElement('div');
    t.className = 'motion-data-toast';
    t.textContent = message;
    document.body.appendChild(t);
    // fade out after timeout
    setTimeout(() => {
        t.style.opacity = '0';
        t.addEventListener('transitionend', () => t.remove());
    }, timeout);
}
