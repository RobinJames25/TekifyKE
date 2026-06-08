# TekifyKE - E-Commerce Platform

A complete, production-ready e-commerce platform for electronics retail in Kenya, built with Next.js 16, React 19, TypeScript, Prisma 7, and Neon Postgres.

## 🚀 Features

### Customer Features
- ✅ **Product Browsing** - Browse electronics with advanced filtering and search
- ✅ **Product Details** - Detailed product pages with image carousels and specifications
- ✅ **Shopping Cart** - Persistent cart with quantity management
- ✅ **Checkout Flow** - 3-step checkout with shipping and payment
- ✅ **Dual Payment Methods** - PayPal and KCB Buni (M-Pesa) integration
- ✅ **Order Tracking** - Real-time order status tracking
- ✅ **Responsive Design** - Mobile-first, works on all devices

### Admin Features
- ✅ **Dashboard** - Comprehensive metrics and analytics
- ✅ **Product Management** - Full CRUD operations for products
- ✅ **Order Management** - View, filter, and update order status
- ✅ **Category Management** - Organize products by categories
- ✅ **Role-Based Access** - Secure admin panel with Clerk authentication
- ✅ **Inventory Tracking** - Low stock alerts and sales analytics

## 🛠️ Tech Stack

### Frontend
- **Next.js 16** - React framework with App Router
- **React 19** - Latest React with Server Components
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first styling
- **Zustand** - State management for cart

### Backend
- **Prisma 7** - Type-safe ORM
- **Neon Postgres** - Serverless PostgreSQL database
- **Clerk** - Authentication and user management
- **Next.js API Routes** - Serverless API endpoints

### Payment Integration
- **PayPal REST API** - International payments
- **KCB Buni API** - M-Pesa payments for Kenya

## 📦 Installation

### Prerequisites
- Node.js 18+ 
- pnpm (recommended) or npm
- Neon Postgres database
- Clerk account
- PayPal developer account (optional)
- KCB Buni merchant account (optional)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/tekifyke.git
cd tekifyke
```

2. **Install dependencies**
```bash
pnpm install
```

3. **Set up environment variables**
```bash
cp .env.example .env
```

Edit `.env` with your credentials:
```env
# Database
DATABASE_URL="your_neon_postgres_url"

# Clerk Authentication
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=your_clerk_publishable_key
CLERK_SECRET_KEY=your_clerk_secret_key

# Application
NEXT_PUBLIC_APP_URL=http://localhost:3000

# PayPal (Optional)
PAYPAL_MODE=sandbox
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret

# KCB Buni (Optional)
KCB_BUNI_BASE_URL=https://uat.buni.kcbgroup.com
KCB_BUNI_CLIENT_ID=your_kcb_client_id
KCB_BUNI_CLIENT_SECRET=your_kcb_client_secret
KCB_BUNI_MERCHANT_CODE=your_merchant_code
KCB_BUNI_TILL_NUMBER=your_till_number
KCB_BUNI_PASSKEY=your_passkey
```

4. **Set up the database**
```bash
# Generate Prisma client
pnpm prisma generate

# Run migrations
pnpm prisma migrate deploy

# Seed the database (optional)
pnpm prisma db seed
```

5. **Run the development server**
```bash
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## 📁 Project Structure

```
tekifyke/
├── prisma/
│   ├── schema.prisma          # Database schema
│   └── seed.ts                # Database seeding script
├── src/
│   ├── app/
│   │   ├── (main)/            # Customer-facing pages
│   │   │   ├── page.tsx       # Landing page
│   │   │   ├── products/      # Product pages
│   │   │   ├── cart/          # Shopping cart
│   │   │   ├── checkout/      # Checkout flow
│   │   │   └── orders/        # Order tracking
│   │   ├── admin/             # Admin dashboard
│   │   │   ├── page.tsx       # Dashboard
│   │   │   ├── products/      # Product management
│   │   │   ├── orders/        # Order management
│   │   │   └── categories/    # Category management
│   │   ├── api/               # API routes
│   │   │   ├── payments/      # Payment endpoints
│   │   │   └── admin/         # Admin endpoints
│   │   ├── globals.css        # Global styles
│   │   └── layout.tsx         # Root layout
│   ├── components/
│   │   ├── layout/            # Layout components
│   │   ├── products/          # Product components
│   │   └── ui/                # UI components
│   ├── lib/
│   │   ├── prisma.ts          # Prisma client
│   │   ├── utils.ts           # Utility functions
│   │   └── store/             # State management
│   └── middleware.ts          # Clerk middleware
├── .env.example               # Environment variables template
├── PAYMENT_INTEGRATION.md     # Payment integration guide
└── README.md                  # This file
```

## 🔐 Authentication & Authorization

### User Roles
- **CUSTOMER** (default) - Can browse and purchase products
- **ADMIN** - Full access to admin dashboard

### Setting Admin Role
In Clerk Dashboard:
1. Go to Users
2. Select a user
3. Click "Metadata"
4. Add to Public Metadata:
```json
{
  "role": "ADMIN"
}
```

## 💳 Payment Integration

### PayPal Setup
1. Create a PayPal developer account
2. Create a sandbox/live app
3. Get Client ID and Secret
4. Add to `.env`
5. Configure return URLs in PayPal dashboard

### KCB Buni Setup
1. Contact KCB for merchant account
2. Get API credentials and till number
3. Add to `.env`
4. Configure callback URL: `https://yourdomain.com/api/payments/kcb-buni/callback`
5. Test with UAT environment first

See [PAYMENT_INTEGRATION.md](./PAYMENT_INTEGRATION.md) for detailed guide.

## 🗄️ Database Schema

### Models
- **User** - Customer accounts (managed by Clerk)
- **Category** - Product categories
- **Product** - Product catalog
- **Order** - Customer orders
- **OrderItem** - Order line items

### Key Relationships
- Products belong to Categories
- Orders belong to Users
- OrderItems link Orders and Products

## 🚀 Deployment

### Vercel (Recommended)
1. Push code to GitHub
2. Import project in Vercel
3. Add environment variables
4. Deploy

### Environment Variables for Production
- Set `PAYPAL_MODE=live` for production PayPal
- Use production KCB Buni URL
- Update `NEXT_PUBLIC_APP_URL` to your domain
- Ensure all secrets are secure

## 📊 Admin Dashboard

Access: `/admin` (requires ADMIN role)

### Features
- **Dashboard** - Revenue, orders, inventory metrics
- **Products** - Create, edit, view products
- **Orders** - View, filter, update order status
- **Categories** - Manage product categories

### Quick Actions
- Add new products
- Process pending orders
- Check low stock alerts
- View sales analytics

## 🧪 Testing

### Manual Testing Checklist
- [ ] User registration and login
- [ ] Product browsing and search
- [ ] Add to cart functionality
- [ ] Checkout flow
- [ ] PayPal payment (sandbox)
- [ ] M-Pesa payment (UAT)
- [ ] Order confirmation
- [ ] Admin dashboard access
- [ ] Product management
- [ ] Order status updates

### Test Accounts
- **PayPal Sandbox**: Use PayPal sandbox buyer account
- **KCB Buni UAT**: Contact KCB for test phone numbers

## 🔧 Development

### Available Scripts
```bash
# Development
pnpm dev              # Start dev server
pnpm build            # Build for production
pnpm start            # Start production server

# Database
pnpm prisma generate  # Generate Prisma client
pnpm prisma migrate   # Run migrations
pnpm prisma studio    # Open Prisma Studio
pnpm prisma db seed   # Seed database

# Code Quality
pnpm lint             # Run ESLint
pnpm type-check       # Run TypeScript check
```

### Code Style
- TypeScript strict mode enabled
- No `any` types allowed
- ESLint + Prettier configured
- Tailwind CSS for styling

## 📝 API Documentation

### Customer APIs
- `POST /api/payments/paypal/create-order` - Create PayPal order
- `GET /api/payments/paypal/capture-order` - Capture PayPal payment
- `POST /api/payments/kcb-buni/stk-push` - Initiate M-Pesa payment
- `POST /api/payments/kcb-buni/callback` - M-Pesa payment callback

### Admin APIs
- `POST /api/admin/products` - Create product
- `GET /api/admin/products` - List products
- `POST /api/admin/orders/[id]/status` - Update order status

## 🐛 Troubleshooting

### Common Issues

**Database Connection Error**
- Verify DATABASE_URL is correct
- Check Neon Postgres is accessible
- Run `pnpm prisma generate`

**Clerk Authentication Error**
- Verify Clerk keys in `.env`
- Check middleware configuration
- Ensure user has correct role metadata

**Payment Integration Error**
- Check API credentials
- Verify callback URLs
- Review payment provider logs
- Check NEXT_PUBLIC_APP_URL is correct

## 📄 License

MIT License - see LICENSE file for details

## 👥 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📞 Support

For issues and questions:
- GitHub Issues: [github.com/yourusername/tekifyke/issues](https://github.com/yourusername/tekifyke/issues)
- Email: support@tekifyke.com

## 🙏 Acknowledgments

- Next.js team for the amazing framework
- Clerk for authentication
- Prisma for the ORM
- Neon for serverless Postgres
- PayPal and KCB for payment APIs

---

Built with ❤️ for the Kenyan tech community
