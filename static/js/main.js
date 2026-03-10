(function () {
    function registerServiceWorker() {
        if (!("serviceWorker" in navigator)) {
            return;
        }

        window.addEventListener("load", function () {
            navigator.serviceWorker.register("/static/service-worker.js").catch(function () {
                // Non-blocking progressive enhancement; keep the UI usable if registration fails.
            });
        });
    }

    function revealContent() {
        const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
        const revealTargets = document.querySelectorAll(
            ".hero-panel, .page-header, .section-heading, .search-panel, .record-card, .event-card, .empty-state, .book-card, .login-card, .edit-event-card"
        );

        if (!revealTargets.length) {
            return;
        }

        revealTargets.forEach(function (element, index) {
            element.classList.add("js-reveal");
            element.style.setProperty("--reveal-delay", `${Math.min(index * 70, 420)}ms`);
        });

        if (prefersReducedMotion.matches || !("IntersectionObserver" in window)) {
            revealTargets.forEach(function (element) {
                element.classList.add("is-visible");
            });
            return;
        }

        const observer = new IntersectionObserver(
            function (entries) {
                entries.forEach(function (entry) {
                    if (!entry.isIntersecting) {
                        return;
                    }

                    entry.target.classList.add("is-visible");
                    observer.unobserve(entry.target);
                });
            },
            { threshold: 0.12, rootMargin: "0px 0px -8% 0px" }
        );

        revealTargets.forEach(function (element) {
            observer.observe(element);
        });
    }

    registerServiceWorker();
    revealContent();
})();
