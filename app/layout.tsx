import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { ClerkProvider } from '@clerk/nextjs';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'TekifyKE - Premium Electronics Store in Kenya',
  description:
    'Shop the latest laptops, smartphones, tablets, and tech accessories in Kenya. Fast delivery in Nairobi within 24 hours. Authentic products with warranty.',
  keywords: [
    'electronics',
    'laptops',
    'smartphones',
    'tablets',
    'Kenya',
    'Nairobi',
    'tech store',
    'Apple',
    'Samsung',
    'Dell',
  ],
  authors: [{ name: 'TekifyKE' }],
  openGraph: {
    title: 'TekifyKE - Premium Electronics Store in Kenya',
    description: 'Shop the latest tech products with fast delivery in Nairobi',
    type: 'website',
    locale: 'en_KE',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ClerkProvider
      appearance={{
        variables: {
          colorPrimary: '#3b82f6',
          colorBackground: '#0f172a',
          colorInputBackground: '#1e293b',
          colorInputText: '#f1f5f9',
        },
      }}
    >
      <html lang="en" className="dark">
        <body className={inter.className}>
          <div className="min-h-screen flex flex-col">
            {children}
          </div>
        </body>
      </html>
    </ClerkProvider>
  );
}

// Made with Bob
