// Enhanced JS: mobile nav, smooth scroll, FAQ accordion, contact form stub, and utilities
document.addEventListener('DOMContentLoaded', () => {
        // Mobile nav toggle with backdrop, scroll-lock, animated icon and focus trap
        const toggle = document.getElementById('mobileMenuToggle');
        const mainNav = document.getElementById('mainNav');
        const sidebarCloseBtn = document.querySelector('.sidebar-close');
        let navBackdrop = null;
        let focusable = [];
        let firstFocusable = null;
        let lastFocusable = null;

        function createBackdrop(){
            if (navBackdrop) return navBackdrop;
            navBackdrop = document.createElement('div');
            navBackdrop.className = 'nav-backdrop';
            document.body.appendChild(navBackdrop);
            // allow fade-in
            requestAnimationFrame(()=> navBackdrop.classList.add('show'));
            return navBackdrop;
        }

        function removeBackdrop(){
            if (!navBackdrop) return;
            navBackdrop.classList.remove('show');
            setTimeout(()=>{ navBackdrop?.remove(); navBackdrop = null; }, 220);
        }

        function lockScroll(){ document.body.classList.add('no-scroll'); }
        function unlockScroll(){ document.body.classList.remove('no-scroll'); }

        function setupFocusables(){
            focusable = Array.from(mainNav.querySelectorAll('a, button, input, [tabindex]:not([tabindex="-1"])'))
                .filter(el => !el.hasAttribute('disabled'));
            firstFocusable = focusable[0] || null;
            lastFocusable = focusable[focusable.length - 1] || null;
        }

        function trapTab(e){
            if (e.key !== 'Tab') return;
            if (!firstFocusable || !lastFocusable) return;
            if (e.shiftKey){
                if (document.activeElement === firstFocusable){ e.preventDefault(); lastFocusable.focus(); }
            } else {
                if (document.activeElement === lastFocusable){ e.preventDefault(); firstFocusable.focus(); }
            }
        }

        function openNav(){
            if (!mainNav) return;
            mainNav.classList.add('open');
            toggle.classList.add('opened');
            toggle.setAttribute('aria-expanded', 'true');
            // change icon from bars to times if using FontAwesome
            const icon = toggle.querySelector('i');
            if (icon && icon.classList.contains('fa-bars')){ icon.classList.remove('fa-bars'); icon.classList.add('fa-times'); }
            createBackdrop()?.addEventListener('click', closeNav);
            lockScroll();
            setupFocusables();
            firstFocusable?.focus();
            document.addEventListener('keydown', trapTab);
        }

        function closeNav(){
            if (!mainNav) return;
            mainNav.classList.remove('open');
            toggle.classList.remove('opened');
            toggle.setAttribute('aria-expanded', 'false');
            const icon = toggle.querySelector('i');
            if (icon && icon.classList.contains('fa-times')){ icon.classList.remove('fa-times'); icon.classList.add('fa-bars'); }
            removeBackdrop();
            unlockScroll();
            toggle.focus();
            document.removeEventListener('keydown', trapTab);
        }

        if (toggle && mainNav) {
                toggle.addEventListener('click', () => {
                                const opened = mainNav.classList.contains('open');
                                if (opened) closeNav(); else openNav();
                });

                // Close menu when any nav link is clicked (mobile behavior)
                mainNav.querySelectorAll('a').forEach(a=>{
                    a.addEventListener('click', (e)=>{
                        // if link is an internal anchor or a page navigation, close the menu
                        if (mainNav.classList.contains('open')) setTimeout(()=> closeNav(), 60);
                    });
                });
        }

        // Dedicated close button inside the sidebar (mobile)
        if (sidebarCloseBtn) {
            sidebarCloseBtn.addEventListener('click', () => {
                if (mainNav.classList.contains('open')) closeNav();
            });
        }

    // Close mobile nav on outside click (keep as a fallback)
    document.addEventListener('click', (e) => {
        if (!mainNav || !toggle) return;
        if (!mainNav.classList.contains('open')) return;
        if (!mainNav.contains(e.target) && !toggle.contains(e.target)) closeNav();
    });

        // Close nav with ESC key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' || e.key === 'Esc') {
                    if (mainNav && mainNav.classList.contains('open')) {
                        closeNav();
                    }
                }
        });

        // Ensure mobile menu state resets when resizing to desktop widths
        window.addEventListener('resize', () => {
            if (!mainNav || !toggle) return;
            if (window.innerWidth > 820 && mainNav.classList.contains('open')) closeNav();
        });

    // Greeting based on time
    const greetingEl = document.getElementById('greeting');
    if (greetingEl) {
        // Always show a single welcome message regardless of the time of day
        greetingEl.textContent = 'WELCOME';
    }

    // Smooth scroll for internal anchors
    document.querySelectorAll('a[href^="#"]').forEach(a => {
        a.addEventListener('click', (e) => {
            const href = a.getAttribute('href');
            if (href && href.startsWith('#')) {
                e.preventDefault();
                const el = document.querySelector(href);
                if (el) el.scrollIntoView({behavior:'smooth',block:'start'});
            }
        });
    });

    // Join  button
    const joinWhatsapp = document.getElementById('joinWhatsapp');
    if (joinWhatsapp) {
        joinWhatsapp.addEventListener('click', () => {
            window.open('https://wa.me/233256342577', '_blank');
        });
    }

    // FAQ accordion
    document.querySelectorAll('.faq .item .question').forEach(q => {
        q.addEventListener('click', () => {
            const item = q.closest('.item');
            const ans = item.querySelector('.answer');
            const opened = ans.style.display === 'block';
            document.querySelectorAll('.faq .item .answer').forEach(a => a.style.display = 'none');
            if (!opened) ans.style.display = 'block';
        });
    });

    // Contact form handler (enhanced)
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        // debounce utility
        function debounce(fn, wait=250){ let t; return (...args)=>{ clearTimeout(t); t = setTimeout(()=>fn.apply(this,args), wait); }; }
        // floating label 'filled' toggles
        const formFields = contactForm.querySelectorAll('.form-field');
        formFields.forEach(ff => {
            const input = ff.querySelector('input,textarea');
            if (!input) return;
            const toggle = () => {
                if (input.value && input.value.length) ff.classList.add('filled'); else ff.classList.remove('filled');
            };
            input.addEventListener('input', toggle);
            input.addEventListener('blur', toggle);
            // init
            toggle();
        });
        const errorEl = document.getElementById('contactError');
        const progress = document.getElementById('contactProgress');
        const progressBar = document.getElementById('contactProgressBar');
        const cancelBtn = document.getElementById('contactCancel');
        const successPanel = document.getElementById('contactSuccess');
        const successClose = document.getElementById('contactSuccessClose');

        let uploadTimer = null;

        function setError(msg){
            if (!errorEl) return;
            if (!msg) { errorEl.style.display = 'none'; errorEl.textContent = ''; }
            else { errorEl.style.display = 'block'; errorEl.textContent = msg; }
        }

    function fakeUpload(file){
            return new Promise((resolve, reject) => {
                if (!file) return resolve(null);
                const sizeMB = file.size / (1024*1024);
                if (sizeMB > 10) return reject(new Error('File too large (max 10MB)'));
                let progress = 0;
                progressBar.style.width = '0%';
                progress.parentElement.style.display = 'block';
                uploadTimer = setInterval(()=>{
                    progress += 10 + Math.random()*15;
                    if (progress > 100) progress = 100;
                    progressBar.style.width = progress + '%';
                    if (progress >= 100) {
                        clearInterval(uploadTimer); uploadTimer = null; setTimeout(()=>{ progress.parentElement.style.display = 'none'; resolve({url:'/_demo/'+file.name}); }, 350);
                    }
                }, 250);
                cancelBtn.style.display = 'inline-block';
            });
        }

    cancelBtn?.addEventListener('click', () => {
            if (uploadTimer) { clearInterval(uploadTimer); uploadTimer = null; }
            progressBar.style.width = '0%';
            progress.style.display = 'none';
            cancelBtn.style.display = 'none';
            setError('Upload canceled');
        });

    contactForm.addEventListener('submit', function (e) {
            e.preventDefault();
            setError('');
            const name = contactForm.name?.value?.trim();
            const email = contactForm.email?.value?.trim();
            const phone = contactForm.phone?.value?.trim();
            const message = contactForm.message?.value?.trim();
            const fileInput = document.getElementById('contactFile');
            const file = fileInput?.files?.[0] || null;
            const subscribe = document.getElementById('contactSubscribe')?.checked;

            // basic validation
            if (!name) return setError('Please provide your name');
            if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return setError('Please provide a valid email');
            if (!message || message.length < 10) return setError('Please provide a longer message (10+ chars)');

            // disable form
            const submitBtn = contactForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true; submitBtn.textContent = 'Sending...';

            // simulate upload then save
            fakeUpload(file).then((uploadInfo) => {
                // demo storage: push to localStorage
                try {
                    const existing = JSON.parse(localStorage.getItem('md_contacts') || '[]');
                    existing.push({name,email,phone,message,subscribe,uploaded:uploadInfo?.url||null,ts:Date.now()});
                    localStorage.setItem('md_contacts', JSON.stringify(existing));
                } catch (err) { console.warn(err); }

                // analytics stub
                console.info('contact:sent', {email,subscribe});

                showToast('Message sent — we will reply shortly');
                contactForm.reset();
                submitBtn.disabled = false; submitBtn.textContent = 'Send Message';

                // show success panel (animated)
                if (successPanel) {
                    successPanel.classList.remove('hidden'); successPanel.classList.add('show'); successPanel.style.display = 'block';
                    successPanel.scrollIntoView({behavior:'smooth'}); successClose?.focus();
                    // auto-hide after 8s
                    setTimeout(()=>{ if (successPanel) { successPanel.classList.remove('show'); successPanel.classList.add('hidden'); setTimeout(()=>{ successPanel.style.display='none'; }, 300); } }, 8000);
                }
            }).catch(err => {
                console.error(err); setError(err.message || 'Could not send message');
                submitBtn.disabled = false; submitBtn.textContent = 'Send Message';
            });
        });

        successClose?.addEventListener('click', () => {
            if (successPanel) { successPanel.classList.remove('show'); successPanel.classList.add('hidden'); setTimeout(()=>{ successPanel.style.display='none'; }, 300); }
        });

        // live validation (debounced)
        const emailInput = document.getElementById('contactEmail');
        const messageInput = document.getElementById('contactMessage');
        const nameInput = document.getElementById('contactName');
        const errEl = document.getElementById('contactError');
        const validateField = debounce(()=>{
            if (!emailInput || !messageInput) return;
            const eVal = emailInput.value.trim();
            if (eVal && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(eVal)) { errEl.textContent = 'Please enter a valid email'; errEl.style.display='block'; errEl.classList.add('shake'); setTimeout(()=>errEl.classList.remove('shake'),400); }
            else { errEl.textContent=''; errEl.style.display='none'; }
        }, 300);
        emailInput?.addEventListener('input', validateField);
        messageInput?.addEventListener('input', debounce(()=>{ if (messageInput.value.trim().length>0) errEl.style.display='none'; },200));

        // scroll-to-top button
        const scrollTopBtn = document.getElementById('scrollTop');
        function checkScroll(){ if (window.scrollY > 240) scrollTopBtn?.classList.add('show'); else scrollTopBtn?.classList.remove('show'); }
        window.addEventListener('scroll', debounce(checkScroll, 80));
        scrollTopBtn?.addEventListener('click', ()=> window.scrollTo({top:0,behavior:'smooth'}));
    }

    // Newsletter subscribe (footer)
    const newsletter = document.getElementById('newsletterForm');
    if (newsletter) {
        newsletter.addEventListener('submit', (e) => {
            e.preventDefault();
            const email = newsletter.querySelector('input[name="email"]').value;
            console.log('Newsletter subscribe', email);
            showToast('Thanks — you are now subscribed.');
            newsletter.reset();
        });
    }

    // Stats count-up animation when scrolled into view
    (function(){
        const statEls = document.querySelectorAll('.stat-value[data-target]');
        if (!statEls || statEls.length === 0) return;

        function animateValue(el, start, end, duration, decimals, suffix) {
            let startTime = null;
            const step = (timestamp) => {
                if (!startTime) startTime = timestamp;
                const progress = Math.min((timestamp - startTime) / duration, 1);
                const value = start + (end - start) * progress;
                el.textContent = (decimals ? value.toFixed(decimals) : Math.round(value)) + (suffix || '');
                if (progress < 1) requestAnimationFrame(step);
            };
            requestAnimationFrame(step);
        }

        const observer = new IntersectionObserver((entries, obs) => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                const el = entry.target;
                const target = parseFloat(el.getAttribute('data-target')) || 0;
                const suffix = el.getAttribute('data-suffix') || '';
                const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
                animateValue(el, 0, target, 1200, decimals, suffix);
                obs.unobserve(el);
            });
        }, { threshold: 0.35 });

        statEls.forEach(el => {
            el.textContent = '0' + (el.getAttribute('data-suffix') || '');
            observer.observe(el);
        });
    })();

    // Generic reveal-on-scroll for sections with staggered children
    (function(){
        const groups = document.querySelectorAll('.reveal-on-scroll');
        if (!groups || groups.length === 0) return;

        const gObserver = new IntersectionObserver((entries, obs) => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                const group = entry.target;
                // add animate class to group (CSS handles final state)
                group.classList.add('animate');

                // Stagger any children that have .reveal-child (for pronounced stagger, add small delays)
                const children = Array.from(group.querySelectorAll('.reveal-child'));
                children.forEach((el, i) => {
                    setTimeout(() => el.classList.add('visible'), i * 120);
                });

                obs.unobserve(group);
            });
        }, { threshold: 0.18 });

        groups.forEach(g => gObserver.observe(g));
    })();

    // Team member bio toggle (click or keyboard)
    (function(){
        const members = document.querySelectorAll('.team-member');
        members.forEach(mem => {
            const btn = mem.querySelector('button');
            if (!btn) return;
            const toggle = () => {
                const expanded = mem.classList.toggle('expanded');
                btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
            };
            btn.addEventListener('click', toggle);
            mem.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
        });
    })();

    // Hero entrance animation: add .animate when hero scrolls into view
    (function(){
        const hero = document.querySelector('.hero');
        if (!hero) return;

        // If hero is already visible on load, animate immediately
        const rect = hero.getBoundingClientRect();
        if (rect.top >= 0 && rect.top < (window.innerHeight || document.documentElement.clientHeight)) {
            hero.classList.add('animate');
            return;
        }

        const hObserver = new IntersectionObserver((entries, obs) => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                entry.target.classList.add('animate');
                obs.unobserve(entry.target);
            });
        }, { threshold: 0.12 });

        hObserver.observe(hero);
    })();
});

function selectService(name) {
    showToast(`${name} selected`);
}

// Generic toast helper if not provided by toast.js
function showToast(msg, t = 3500) {
    if (window.showToast && window.showToast !== showToast) return window.showToast(msg, t);
    const el = document.createElement('div');
    el.className = 'motion-data-toast';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.addEventListener('transitionend', () => el.remove()); }, t);
}
