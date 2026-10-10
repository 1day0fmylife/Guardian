---
version: alpha
name: Guardian
description: Dense, quiet secure-access administration using the existing Guardian shell.
colors:
  primary: '#111827'
  background: '#f5f6f8'
  surface: '#ffffff'
  text: '#15171a'
  muted: '#667085'
  danger: '#b42318'
  success: '#027a48'
typography:
  sans:
    fontFamily: 'Roboto, system-ui, sans-serif'
  mono:
    fontFamily: 'ui-monospace, monospace'
rounded:
  dialog: '12px'
spacing:
  content: '28px 32px'
components:
  button: {}
  table: {}
  dialog: {}
---

# Guardian design context

Guardian operators inspect device identity, desired policy and observed tunnel state.
Preserve the established light/dark administration shell, Roboto, Material Symbols,
semantic badges, labeled controls and horizontally scrollable tables. The distinguishing
service view is a three-row access matrix with explicit decision reasons and revisions.
Do not introduce a marketing visual language or replace sibling layouts.

`web/src/styles.css` is the canonical runtime token owner; values above document its
existing light theme. Dark overrides live in that same file. Feature CSS consumes those
variables. No token generator or independent theme system is introduced.

Panels and tables use borders for hierarchy. Primary buttons commit, secondary buttons
operate in context. Service confirmations use native modal dialog with cancellation
focus, Escape and focus restoration. Disabled, busy, error and read-only states retain
text semantics. Existing EN copy is retained: no locale provider currently exists.
QR codes deliberately use a white background in both themes for camera readability.
Forms grow with content and tables own horizontal overflow. Motion is not needed.
