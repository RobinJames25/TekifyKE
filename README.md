# TekifyKE

A full-stack electroni store platform built with Node.js, Express, Prisma, and React.

## Project Structure

- **Backend**: Node.js + Express + Prisma + PostgreSQL
- **Frontend**: React + Vite

---

## Backend Setup

### Prerequisites

- Node.js (v16 or higher)
- PostgreSQL
- pnpm

### Installation Steps

1. Navigate to the backend folder:

```bash
cd Backend
```

2. Install dependencies:

```bash
pnpm install
```

3. Approve Prisma build scripts:

```bash
pnpm approve-builds
```

4. Create a `.env` file in the `Backend` directory:

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/tekifyke_db"
PORT=5000
JWT_SECRET="your-secret-key-here"
```

5. Run database migrations:

```bash
pnpm prisma migrate dev
pnpm prisma generate
```

6. Start the development server:

```bash
pnpm run dev
```

The backend server will run on `http://localhost:5000`

---

## Frontend Setup

### Installation Steps

1. Navigate to the frontend folder:

```bash
cd Frontend
```

2. Install dependencies:

```bash
pnpm install
```

3. Create a `.env` file in the `Frontend` directory:

```env
VITE_API_URL="http://localhost:5000/api"
```

4. Start the development server:

```bash
pnpm run dev
```

The frontend app will run on `http://localhost:5173`

---

## Developer Onboarding

### Quick Start

1. Clone the repository:

```bash
git clone https://github.com/RobinJames25/TekifyKE.git
cd TekifyKE
```

2. Set up the backend:

```bash
cd Backend
pnpm install
pnpm approve-builds
cp .env.example .env
# Edit .env with your database credentials
pnpm prisma migrate dev
pnpm prisma generate
pnpm run dev
```

3. Set up the frontend (in a new terminal):

```bash
cd Frontend
pnpm install
cp .env.example .env
# Edit .env with your API URL
pnpm run dev
```

---

## Prisma Commands

### Useful Commands

- **Approve Prisma builds**: `pnpm approve-builds`
- **Create migration**: `pnpm prisma migrate dev`
- **Generate Prisma Client**: `pnpm prisma generate`
- **Open Prisma Studio**: `pnpm prisma studio`
- **Reset database**: `pnpm prisma migrate reset`

---

## License

This project is licensed under the MIT License.
