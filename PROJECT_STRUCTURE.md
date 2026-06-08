# TekifyKE - Project Structure Documentation

## 📁 Complete Folder Structure (src/ directory)

```
TekifyKE/
├── src/
│   ├── middleware.ts                    # Clerk authentication & role-based routing
│   │
│   ├── app/                             # Next.js 16 App Router
│   │   ├── globals.css                  # Global styles with dark-mode design system
│   │   ├── layout.tsx                   # Root layout with ClerkProvider
│   │   │
│   │   └── (main)/                      # Main app group with Navbar & Footer
│   │       ├── layout.tsx               # Layout wrapper with navigation
│   │       ├── page.tsx                 # Landing page (Hero, Categories, Featured Products)
│   │       ├── loading.tsx              # Skeleton loading states
│   │       └── error.tsx                # Error boundary
│   │
│   ├── components/                      # Reusable React components
│   │   ├── layout/
│   │   │   ├── navbar.tsx              # Responsive navigation with cart count
│   │   │   └── footer.tsx              # Footer with links and contact info
│   │   │
│   │   └── ui/                         # Shadcn-style UI components
│   │       ├── button.tsx              # Button with variants (default, outline, ghost, etc.)
│   │       └── card.tsx                # Card with Header, Title, Content, Footer
│   │
│   └── lib/                            # Utility functions and configurations
│       ├── prisma.ts                   # Prisma client singleton
│       ├── utils.ts                    # Helper functions (cn, formatPrice, formatDate, slugify)
│       │
│       └── store/
│           └── cart-store.ts           # Zustand cart state management
│
├── prisma/
│   ├── schema.prisma                   # Database schema (User, Product, Category, Order, OrderItem)
│   ├── seed.ts                         # Database seed with realistic tech inventory
│   └── prisma.config.ts                # Neon Postgres configuration
│
├── Backend/                            # Legacy backend (can be removed)
├── Frontend/                           # Legacy frontend (can be removed)
│
├── .env.example                        # Environment variables template
├── .gitignore                          # Git ignore rules
├── next.config.ts                      # Next.js configuration
├── tailwind.config.ts                  # Tailwind CSS configuration
├── tsconfig.json                       # TypeScript configuration (paths: @/*)
├── postcss.config.mjs                  # PostCSS configuration
├── package.json                        # Dependencies and scripts
└── README.md                           # Project documentation
```

## 🗂️ Directory Explanations

### `/src` - Source Directory
All application code lives here. This is the modern Next.js convention for better organization.

### `/src/middleware.ts`
- **Purpose**: Authentication and authorization
- **Features**:
  - Clerk authentication integration
  - Role-based route protection (ADMIN vs CUSTOMER)
  - Public route matching
  - Redirect logic for unauthorized access

### `/src/app` - Next.js App Router
- **Purpose**: Application routes and pages
- **Key Files**:
  - `globals.css`: Dark-mode-first design system with CSS variables
  - `layout.tsx`: Root layout with ClerkProvider and metadata
  - `(main)/`: Route group with shared navigation layout

### `/src/components` - React Components
- **Purpose**: Reusable UI components
- **Structure**:
  - `layout/`: Navigation and footer components
  - `ui/`: Base UI components (Button, Card, Input, etc.)

### `/src/lib` - Utilities & Configurations
- **Purpose**: Helper functions and shared logic
- **Key Files**:
  - `prisma.ts`: Database client with singleton pattern
  - `utils.ts`: Common utilities (className merging, formatting)
  - `store/cart-store.ts`: Global cart state with Zustand

### `/prisma` - Database Layer
- **Purpose**: Database schema and migrations
- **Key Files**:
  - `schema.prisma`: Complete data models
  - `seed.ts`: Realistic product inventory for Kenya market
  - `prisma.config.ts`: Neon Serverless Postgres configuration

## 🎨 Design System

### Color Palette (Dark Mode First)
```css
--background: 222.2 84% 4.9%        /* Dark background */
--foreground: 210 40% 98%           /* Light text */
--primary: 217.2 91.2% 59.8%        /* Blue accent */
--secondary: 217.2 32.6% 17.5%      /* Dark gray */
--muted: 217.2 32.6% 17.5%          /* Muted elements */
--destructive: 0 62.8% 30.6%        /* Red for errors */
```

### Typography
- **Font**: Inter (Google Fonts)
- **Sizes**: Responsive with Tailwind classes
- **Weights**: 400 (regular), 500 (medium), 600 (semibold), 700 (bold)

### Components
- **Buttons**: 5 variants (default, destructive, outline, secondary, ghost, link)
- **Cards**: Modular with Header, Title, Description, Content, Footer
- **Spacing**: Consistent 4px grid system

## 🔐 Authentication Flow

### Clerk Integration
1. **Public Routes**: `/`, `/products`, `/sign-in`, `/sign-up`
2. **Protected Routes**: `/cart`, `/checkout`, `/orders`
3. **Admin Routes**: `/admin/*` (requires ADMIN role)

### Role-Based Access
- **CUSTOMER**: Default role, can browse and purchase
- **ADMIN**: Full access to dashboard and management features

## 🛒 Cart Management

### Zustand Store
- **State**: Array of cart items with quantity
- **Actions**: addItem, removeItem, updateQuantity, clearCart
- **Persistence**: LocalStorage with `tekifyke-cart` key
- **Computed**: getTotalItems(), getTotalPrice()

## 📊 Database Models

### User
- Clerk integration via `clerkId`
- Role-based access (ADMIN/CUSTOMER)
- One-to-many with Orders

### Product
- Images array for multiple photos
- JSON attributes for tech specs (RAM, Storage, etc.)
- Stock tracking
- Featured flag for homepage
- Belongs to Category

### Category
- SEO-friendly slugs
- One-to-many with Products

### Order
- Status tracking (PENDING, PAID, SHIPPED, DELIVERED)
- Payment method (PAYPAL, KCB_BUNI)
- Transaction reference for payment tracking
- JSON shipping address

### OrderItem
- Links Orders to Products
- Quantity and price snapshot

## 🚀 Getting Started

### 1. Install Dependencies
```bash
pnpm install
```

### 2. Set Up Environment Variables
Copy `.env.example` to `.env` and fill in:
- `DATABASE_URL`: Neon Postgres connection string
- `DIRECT_URL`: Direct Postgres connection (for migrations)
- Clerk keys (publishable and secret)
- PayPal credentials
- KCB Buni API credentials

### 3. Initialize Database
```bash
pnpm prisma:generate
pnpm prisma:migrate
pnpm prisma:seed
```

### 4. Run Development Server
```bash
pnpm dev
```

Visit `http://localhost:3000`

## 📦 Key Dependencies

### Core
- **Next.js 16**: React framework with App Router
- **React 19**: Latest React with Server Components
- **TypeScript 5.7**: Type safety

### Database
- **Prisma 7**: ORM with Neon Postgres support
- **@prisma/client**: Database client

### Authentication
- **@clerk/nextjs**: Authentication provider

### UI & Styling
- **Tailwind CSS**: Utility-first CSS
- **class-variance-authority**: Component variants
- **clsx + tailwind-merge**: Conditional classes

### State Management
- **Zustand**: Lightweight state management for cart

### Payments
- **@paypal/checkout-server-sdk**: PayPal integration
- **axios**: HTTP client for KCB Buni API

### Icons
- **lucide-react**: Modern icon library

### Image Carousel
- **embla-carousel-react**: Touch-friendly carousels

## 🎯 Next Steps

### Immediate Tasks
1. ✅ Set up environment variables
2. ✅ Run database migrations and seed
3. ⏳ Build products listing page with filters
4. ⏳ Create product detail page with image carousel
5. ⏳ Implement shopping cart page
6. ⏳ Build checkout flow
7. ⏳ Integrate PayPal payment
8. ⏳ Integrate KCB Buni mobile money
9. ⏳ Create admin dashboard
10. ⏳ Build product management CRUD

### Future Enhancements
- Order tracking system
- Email notifications
- Product reviews and ratings
- Wishlist functionality
- Advanced search with filters
- Analytics dashboard
- Inventory management
- Multi-currency support

## 📝 Code Standards

### TypeScript
- Strict mode enabled
- No `any` types
- Proper type definitions for all functions

### React
- Server Components by default
- Client Components only when needed (`'use client'`)
- Async/await for data fetching
- Error boundaries for all routes

### Styling
- Tailwind utility classes
- Dark mode first approach
- Responsive design (mobile-first)
- Consistent spacing and typography

### File Naming
- `kebab-case` for files and folders
- `PascalCase` for React components
- `camelCase` for functions and variables

## 🔧 Available Scripts

```bash
pnpm dev              # Start development server
pnpm build            # Build for production
pnpm start            # Start production server
pnpm lint             # Run ESLint
pnpm prisma:generate  # Generate Prisma client
pnpm prisma:migrate   # Run database migrations
pnpm prisma:studio    # Open Prisma Studio
pnpm prisma:seed      # Seed database with sample data
```

## 📞 Support

For issues or questions:
- Email: support@tekifyke.com
- Phone: +254 700 000 000
- Location: Nairobi, Kenya

---

**Built with ❤️ for the Kenyan tech community**