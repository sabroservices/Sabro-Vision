---
version: "alpha"
name: "Sabro Vision Obsidian Glass"
description: "Ultra HD Cinematic Dark Design System for SABRO VISION IPTV Streaming & Subscriber Platform"

colors:
  primary: "#06B6D4"
  primary-glow: "rgba(6, 182, 212, 0.45)"
  primary-dark: "#0891B2"
  secondary: "#6366F1"
  accent: "#8B5CF6"
  canvas: "#03060D"
  surface: "#070B14"
  card: "#0D1322"
  card-hover: "#131C30"
  border: "#1E293B"
  border-highlight: "rgba(6, 182, 212, 0.35)"
  text-primary: "#F8FAFC"
  text-secondary: "#94A3B8"
  text-muted: "#64748B"
  success: "#10B981"
  warning: "#F59E0B"
  danger: "#EF4444"
  tv-focus: "#00D2FF"

typography:
  headline:
    fontFamily: "'Plus Jakarta Sans', sans-serif"
    fontSize: "32px"
    fontWeight: 800
    lineHeight: 1.2
    letterSpacing: "-0.03em"
  subtitle:
    fontFamily: "'Plus Jakarta Sans', sans-serif"
    fontSize: "18px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "-0.01em"
  body:
    fontFamily: "'Plus Jakarta Sans', sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "0em"
  mono:
    fontFamily: "'JetBrains Mono', monospace"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.02em"
  label:
    fontFamily: "'Plus Jakarta Sans', sans-serif"
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.05em"

rounded:
  xs: "4px"
  sm: "6px"
  md: "10px"
  lg: "16px"
  xl: "24px"
  full: "9999px"

spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  2xl: "48px"

components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "#03060D"
    typography: "{typography.label}"
    rounded: "{rounded.lg}"
    padding: "12px 24px"
  stream-card:
    backgroundColor: "{colors.card}"
    borderColor: "{colors.border}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
    padding: "16px"
  tv-focus-state:
    borderColor: "{colors.tv-focus}"
    outline: "3px solid {colors.tv-focus}"
    scale: "1.04"
---

# SABRO VISION Design System Specification

## 1. Overview
SABRO VISION is an Ultra HD IPTV streaming and subscriber management platform designed for television screens (Android TV, Samsung Tizen, LG webOS), mobile devices, and high-performance desktop web viewing. The aesthetic archetype is **Obsidian Glass**: deep space blacks (`#03060D`) layered with razor-thin cybernetic borders and neon cyan accents (`#06B6D4`). 

The interface emphasizes content immersion: when watching video, the UI recedes completely; when browsing, high-contrast badges, glowing focus indicators, and tabular metrics provide effortless remote-control navigation and touch ergonomics.

## 2. Colors
- **Canvas (`#03060D`):** Deepest obsidian canvas engineered to eliminate backlight bloom on OLED displays.
- **Surface (`#070B14`) & Card (`#0D1322`):** Elevated container surfaces with 1px hairline slate borders (`#1E293B`).
- **Primary Cyan (`#06B6D4`):** Represents connectivity, active stream health, and primary action affordance.
- **TV Focus (`#00D2FF`):** High-intensity neon cyan reserved strictly for D-Pad and remote navigation focus outlines.
- **Live Emerald (`#10B981`):** Indicates active online stream feeds and verified payment transactions.
- **Warning Amber (`#F59E0B`):** Alerts users to subscriptions expiring within 48 hours.
- **Danger Rose (`#EF4444`):** Indicates offline streams, expired credentials, or administrative revoking.

## 3. Typography
- **Primary Interface:** Plus Jakarta Sans. Clean geometric humanist sans-serif with wide aperture, ensuring legibility at 10-foot viewing distances on Smart TVs.
- **Data & Credentials:** JetBrains Mono with tabular numbers (`tnum`) for account expiration countdowns, PPPoE credentials, bitrate statistics, and M3U token keys.
- **Contrast Ratios:** Primary text on obsidian background exceeds 16:1, far surpassing WCAG AAA (7:1) requirements.

## 4. Layout & Spacing
- **Base Grid:** 8px rhythm. Micro elements use 4px increments; macroscopic cards use 16px/24px gutters.
- **Mobile First:** Single-column layout with fixed bottom navigation bar (Home, TV, Packages, Account) within thumb reach.
- **Desktop & Smart TV:** Dual-pane split: left collapsible navigation rail + right expansive 16:9 cinematic video canvas with category channels rail.

## 5. Elevation & Depth
- Elevation is established through translucent dark layers and subtle backdrop blurs (`backdrop-filter: blur(12px)`) rather than muddy drop shadows.
- Active items project a soft radial cyan glow (`box-shadow: 0 0 25px rgba(6, 182, 212, 0.35)`).

## 6. Shapes
- Ergonomic rounded corners: cards and modals use `16px` (`rounded-2xl`), interactive buttons use `10px`-`12px` (`rounded-xl`), and status badges use pill shapes (`rounded-full`).
- TV Focus states apply a non-distorting `scale(1.04)` transform with smooth 200ms easing.

## 7. Components
- **Keycap Login & Instant Auth:** Minimalist single-field code entry with automatic formatting and instant redirect.
- **Stream Player Frame:** Integrated HLS.js video engine with custom HUD overlay, volume sliders, stream quality selector, and channel switcher drawer.
- **Remote D-Pad Navigation:** Strict spatial navigation logic responding to standard TV remote keys (`ArrowUp`, `ArrowDown`, `ArrowLeft`, `ArrowRight`, `Enter`, `Back`).

## 8. Do's and Don'ts
- **DO:** Maintain minimum 44x44px touch targets on all interactive buttons.
- **DO:** Provide visual focus indicators on all focusable elements for keyboard and TV remote users.
- **DO:** Allow user viewport zooming on mobile devices to satisfy WCAG 1.4.4.
- **DON'T:** Never use low-contrast gray-on-dark text (< 4.5:1 ratio).
- **DON'T:** Never obscure the video viewport with persistent non-dismissible banners.
- **DON'T:** Never use 0ms instant transition snaps on interactive cards.
