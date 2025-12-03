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

3. Approve Prisma build scripts (select both when prompted):

```bash
pnpm approve-builds
```

   **Note:** When prompted, make sure to select both Prisma build scripts to approve.

4. Create a `.env` file in the `Backend` directory:

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/tekifyke_db"
PORT=5000
JWT_SECRET="your-secret-key-here"
```

5. Run database migrations:

```bash
pnpm prisma migrate dev --name init
pnpm prisma generate
```

   **Note:** Use descriptive migration names like `--name add_user_table` or `--name update_product_schema`

6. Start the development server:

```bash
pnpm run dev
```

The backend server will run on `http://localhost:5000`

---

## Frontend Setup

### Steps

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

## Running Both Servers Concurrently

### Quick Start (Recommended)

From the root directory, you can run both backend and frontend servers simultaneously:

1. Install root dependencies:

```bash
pnpm install
```

2. Run both servers:

```bash
pnpm run dev
```

This will start:

- Backend on `http://localhost:5000`
- Frontend on `http://localhost:5173`

### Other Useful Scripts

- **Run backend only**: `pnpm run dev:backend`
- **Run frontend only**: `pnpm run dev:frontend`
- **Install all dependencies**: `pnpm run install:all`
- **Run Prisma migrations**: `pnpm run prisma:migrate`
- **Generate Prisma Client**: `pnpm run prisma:generate`
- **Open Prisma Studio**: `pnpm run prisma:studio`

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
pnpm approve-builds  # Select both Prisma builds when prompted
cp .env.example .env
# Edit .env with your database credentials
pnpm prisma migrate dev --name init
pnpm prisma generate
```

3. Set up the frontend:

```bash
cd Frontend
pnpm install
cp .env.example .env
# Edit .env with your API URL
```

4. Run both servers from root:

```bash
cd ..
pnpm install
pnpm run dev
```

---

## Prisma Commands

### Useful Commands

- **Approve Prisma builds**: `pnpm approve-builds` (select both when prompted)
- **Create migration**: `pnpm prisma migrate dev --name <descriptive_name>`
- **Generate Prisma Client**: `pnpm prisma generate`
- **Open Prisma Studio**: `pnpm prisma studio`
- **Reset database**: `pnpm prisma migrate reset`

---

## License

This project is licensed under the MIT License.
