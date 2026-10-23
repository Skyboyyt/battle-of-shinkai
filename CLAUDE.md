# CLAUDE.md — Development & UI/UX Standards

These are the owner's standing standards. Apply them to every website or web application you build, redesign or change in this project, unless the owner explicitly asks for something different.

**Goal:** distinctive, professional, production-quality software that feels thoughtfully designed, impresses clients and works reliably for real users.

## This repository

- The `gh-pages` branch holds the generated Unity WebGL build of *Battle of Shinkai*, published on GitHub Pages; the game's source is not in this repository (see README.md).
- The web standards below apply to the HTML, CSS and scripts served around the game. The Unity build itself comes from its own toolchain.

---

## 1. Stack

- **TypeScript** everywhere with `strict: true`. No plain JavaScript files.
- **React** for every frontend. Use **Next.js** (App Router) when routing, SSR/SSG, SEO or API routes benefit the project.
- **Tailwind CSS** for styling and responsive layout.
- **shadcn/ui** for components. Treat generated components as owned code and restyle them to the project's identity; never ship the stock look.
- **Motion for React** for animation (`motion` package, import from `motion/react`).
- **Lucide React** (`lucide-react`) for icons. Use one icon set only.
- **Backend:** TypeScript on Node.js with a suitable framework (Next.js route handlers / server actions when it lives in the same app).
- Add other technology only when the project genuinely requires it. Avoid unnecessary dependencies.
- **Existing projects on a different stack:** keep compatibility. Explain any migration and get approval before changing the architecture.

## 2. Design language

Linear-inspired minimalism combined with Apple-inspired elegance:

- Clean, sophisticated layouts with generous, consistent spacing (one spacing scale).
- Excellent typography: a deliberate type scale, comfortable line lengths, clear weights.
- A carefully chosen palette defined as design tokens (CSS variables) and used everywhere.
- Clear visual hierarchy; subtle borders and refined, low-contrast shadows.
- Smooth micro-interactions on interactive elements.
- Consistent sizing of controls, radii and icons.
- Material Design 3 principles where they improve complex application workflows (dense forms, data views, multi-step flows).

Do **not** copy Linear, Apple or any template. Give each project its own visual identity suited to its purpose and audience. Every design decision must serve a purpose.

## 3. Never ship

- Decorative arrows that don't indicate navigation
- Excessive gradients, glows or neon effects
- Repetitive or oversized card grids
- Random floating or blob elements
- Generic hero sections (gradient headline + two buttons + device mockup)
- Excessive or attention-seeking animation
- Cramped or inconsistent spacing
- Placeholder text, lorem ipsum, or invented testimonials and statistics
- Labels such as "Prototype", "Demo" or "Portfolio Testing" unless the owner asks for them; never describe the project as a prototype
- Unnecessary branding

## 4. Navigation, theming, responsiveness, accessibility

- **Mobile navigation:** a working hamburger menu where appropriate — opens and closes reliably, closes on Escape and on route change, manages focus, locks background scroll while open.
- **Dark and light modes:** both fully working with consistent styling; respect the system preference, persist the user's choice, no flash of the wrong theme on load.
- **Responsive:** works across mobile, tablet and desktop. Check at roughly 375px, 768px and 1280px+.
- **Accessible:** semantic HTML, full keyboard support, visible focus states, labelled controls, WCAG AA contrast.
- **Touch targets:** at least 44×44px on mobile.

## 5. Animation

- Animate only where it improves the experience: subtle page transitions, hover and press feedback, smooth navigation, refined state changes.
- Respect `prefers-reduced-motion` (e.g. wrap the app in `<MotionConfig reducedMotion="user">`).
- Prefer animating `transform` and `opacity`. Never sacrifice performance for visual effects.

## 6. Functional quality

- No fake buttons, dead links or nonfunctional controls. Every control does something real.
- Validate forms properly on client and server, with clear inline error messages.
- Loading, empty and error states for all asynchronous UI.
- Never expose API keys, passwords or other secrets: keep them server-side in environment variables, out of client bundles and out of commits.
- Reusable, typed components and a maintainable structure.
- Optimize images (`next/image`, correct sizes, modern formats) and loading performance.
- SEO where applicable: metadata, semantic headings, Open Graph tags, sitemap.
- Use authentic, relevant images and meaningful content.

## 7. Workflow

**New websites**

1. Understand the purpose and intended audience.
2. Choose a visual direction within the design language above.
3. Establish the system: color tokens, typography, spacing, radii, shadows, components.
4. Build with the stack above.
5. Refine mobile responsiveness and interactions.
6. Test functionality and performance.
7. Review the result for anything generic, unnecessary or unfinished, and fix it.

**Existing projects**

- Inspect the codebase before changing anything.
- Preserve existing functionality. Don't redesign unnecessarily or remove working features without a clear reason.

## 8. Definition of done

- Type check, lint and production build all pass with no errors.
- Key flows are tested. Never claim a feature works unless it is implemented and tested.
- Checked in light and dark mode, and at mobile and desktop widths.
- **Deploying:** verify the deployment succeeded and report the working URL. Never claim a deployment that did not succeed.
- Polished, ready for real users and good enough to impress clients — never at the expense of functionality.
