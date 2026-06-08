import { auth, currentUser } from '@clerk/nextjs/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Check authentication
  const { userId } = await auth();
  if (!userId) {
    redirect('/sign-in');
  }

  // Get user details
  const user = await currentUser();
  
  // Check if user has ADMIN role in metadata
  const userRole = user?.publicMetadata?.role as string | undefined;
  
  if (userRole !== 'ADMIN') {
    redirect('/');
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Admin Header */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-50">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link href="/admin" className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-sm">T</span>
                </div>
                <span className="text-xl font-bold text-white">TekifyKE Admin</span>
              </Link>
              
              <nav className="hidden md:flex items-center space-x-1">
                <Link
                  href="/admin"
                  className="px-4 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
                >
                  Dashboard
                </Link>
                <Link
                  href="/admin/products"
                  className="px-4 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
                >
                  Products
                </Link>
                <Link
                  href="/admin/orders"
                  className="px-4 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
                >
                  Orders
                </Link>
                <Link
                  href="/admin/categories"
                  className="px-4 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
                >
                  Categories
                </Link>
              </nav>
            </div>

            <div className="flex items-center space-x-4">
              <Link
                href="/"
                className="px-4 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 transition-colors"
              >
                View Store
              </Link>
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">
                    {user?.firstName?.[0] || 'A'}
                  </span>
                </div>
                <span className="text-sm text-gray-300 hidden md:block">
                  {user?.firstName || 'Admin'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Admin Content */}
      <main className="container mx-auto px-4 py-8">
        {children}
      </main>

      {/* Admin Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-auto">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between text-sm text-gray-400">
            <p>© 2024 TekifyKE Admin Panel. All rights reserved.</p>
            <div className="flex items-center space-x-4">
              <span>Version 1.0.0</span>
              <span>•</span>
              <Link href="/admin/help" className="hover:text-white transition-colors">
                Help
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

// Made with Bob
