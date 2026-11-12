/**
 * Sabro Vision - Smart TV Spatial Navigation & Remote Control Engine
 * Supports Samsung Tizen, LG webOS, Android TV, Fire TV, and Standard D-Pads.
 */

class SmartTVNavigator {
    constructor() {
        this.focusableSelector = '[data-tv-focus="true"], .tv-focusable, button, a, [tabindex="0"]';
        this.currentFocused = null;
        this.numberBuffer = "";
        this.numberTimeout = null;
        this.osdTimeout = null;
        this.init();
    }

    init() {
        // Register keydown listener
        window.addEventListener('keydown', (e) => this.handleKeyDown(e));

        // Click focus synchronization
        document.addEventListener('mouseover', (e) => {
            const el = e.target.closest(this.focusableSelector);
            if (el && el !== this.currentFocused) {
                this.setFocus(el, false);
            }
        });

        // Initial focus on load
        window.addEventListener('DOMContentLoaded', () => {
            this.focusInitialElement();
        });
    }

    focusInitialElement() {
        const initial = document.querySelector('.tv-default-focus') || 
                        document.querySelector('[data-tv-focus="true"]') ||
                        document.querySelector(this.focusableSelector);
        if (initial) {
            this.setFocus(initial, true);
        }
    }

    setFocus(el, shouldScroll = true) {
        if (!el) return;
        if (this.currentFocused) {
            this.currentFocused.classList.remove('tv-focused', 'ring-4', 'ring-cyan-400', 'scale-105', 'shadow-2xl', 'shadow-cyan-500/50');
        }
        this.currentFocused = el;
        el.classList.add('tv-focused', 'ring-4', 'ring-cyan-400', 'scale-105', 'shadow-2xl', 'shadow-cyan-500/50');
        el.focus();

        if (shouldScroll) {
            el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
        }
    }

    handleKeyDown(e) {
        const key = e.key;
        const code = e.keyCode;

        // 1. Digital Number Keys (0-9) - Direct Channel Number Tuning
        if ((code >= 48 && code <= 57) || (code >= 96 && code <= 105)) {
            const digit = (code >= 96) ? String(code - 96) : key;
            this.handleNumberInput(digit);
            return;
        }

        // 2. Navigation Keys
        switch (key) {
            case 'ArrowUp':
            case 'Up':
                e.preventDefault();
                this.navigateDirection('up');
                break;
            case 'ArrowDown':
            case 'Down':
                e.preventDefault();
                this.navigateDirection('down');
                break;
            case 'ArrowLeft':
            case 'Left':
                e.preventDefault();
                this.navigateDirection('left');
                break;
            case 'ArrowRight':
            case 'Right':
                e.preventDefault();
                this.navigateDirection('right');
                break;

            case 'Enter':
            case 'Select':
            case 'Ok':
                // Let native click fire if button/anchor, or trigger click
                if (this.currentFocused) {
                    this.currentFocused.click();
                    if (window.onTvEnterPress) {
                        window.onTvEnterPress(this.currentFocused);
                    }
                }
                break;

            // Back Keys (Android Back, Samsung 10009, LG 461, Escape, Backspace)
            case 'Escape':
            case 'Backspace':
            case 'Back':
            case 'GoBack':
                if (code === 10009 || code === 461 || key === 'Escape' || (key === 'Backspace' && document.activeElement.tagName !== 'INPUT')) {
                    e.preventDefault();
                    if (window.onTvBackPress) {
                        window.onTvBackPress();
                    } else {
                        // Default behavior: return to home or toggle OSD
                        window.location.href = '/';
                    }
                }
                break;

            // Channel Up / Down
            case 'PageUp':
            case 'ChannelUp':
            case 'TrackNext':
                e.preventDefault();
                if (window.tuneNextChannel) window.tuneNextChannel();
                break;

            case 'PageDown':
            case 'ChannelDown':
            case 'TrackPrevious':
                e.preventDefault();
                if (window.tunePrevChannel) window.tunePrevChannel();
                break;

            // Media Play/Pause
            case 'MediaPlayPause':
            case 'Play':
            case 'Pause':
                e.preventDefault();
                if (window.toggleTvPlayPause) window.toggleTvPlayPause();
                break;

            // Info Key ('i' or '?')
            case 'i':
            case 'I':
            case '?':
                if (window.toggleTvOsd) window.toggleTvOsd();
                break;
        }
    }

    navigateDirection(direction) {
        const elements = Array.from(document.querySelectorAll(this.focusableSelector)).filter(el => {
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 && window.getComputedStyle(el).display !== 'none';
        });

        if (elements.length === 0) return;
        if (!this.currentFocused || !elements.includes(this.currentFocused)) {
            this.setFocus(elements[0]);
            return;
        }

        const curRect = this.currentFocused.getBoundingClientRect();
        const curCenter = {
            x: curRect.left + curRect.width / 2,
            y: curRect.top + curRect.height / 2
        };

        let bestCandidate = null;
        let minScore = Infinity;

        elements.forEach(candidate => {
            if (candidate === this.currentFocused) return;
            const cRect = candidate.getBoundingClientRect();
            const cCenter = {
                x: cRect.left + cRect.width / 2,
                y: cRect.top + cRect.height / 2
            };

            const dx = cCenter.x - curCenter.x;
            const dy = cCenter.y - curCenter.y;

            let inDirection = false;
            let primaryDist = 0;
            let secondaryDist = 0;

            if (direction === 'up' && dy < -5) {
                inDirection = true;
                primaryDist = -dy;
                secondaryDist = Math.abs(dx);
            } else if (direction === 'down' && dy > 5) {
                inDirection = true;
                primaryDist = dy;
                secondaryDist = Math.abs(dx);
            } else if (direction === 'left' && dx < -5) {
                inDirection = true;
                primaryDist = -dx;
                secondaryDist = Math.abs(dy);
            } else if (direction === 'right' && dx > 5) {
                inDirection = true;
                primaryDist = dx;
                secondaryDist = Math.abs(dy);
            }

            if (inDirection) {
                // Weight secondary distance higher to favor straight-line navigation
                const score = primaryDist + secondaryDist * 2.5;
                if (score < minScore) {
                    minScore = score;
                    bestCandidate = candidate;
                }
            }
        });

        if (bestCandidate) {
            this.setFocus(bestCandidate);
        }
    }

    handleNumberInput(digit) {
        this.numberBuffer += digit;
        clearTimeout(this.numberTimeout);

        const banner = document.getElementById('tvNumberBanner');
        const digitsEl = document.getElementById('tvNumberDigits');
        if (banner && digitsEl) {
            digitsEl.textContent = this.numberBuffer;
            banner.classList.remove('hidden');
        }

        this.numberTimeout = setTimeout(() => {
            const chNum = parseInt(this.numberBuffer);
            this.numberBuffer = "";
            if (banner) banner.classList.add('hidden');

            if (window.tuneChannelByNumber) {
                window.tuneChannelByNumber(chNum);
            }
        }, 1200);
    }
}

// Instantiate globally
window.tvNav = new SmartTVNavigator();
