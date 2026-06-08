import { prisma } from '@/lib/prisma';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import Image from 'next/image';

export const metadata = {
  title: 'Categories - Admin Dashboard',
  description: 'Manage product categories in TekifyKE',
};

export default async function AdminCategoriesPage() {
  // Fetch categories with product count
  const categories = await prisma.category.findMany({
    include: {
      _count: {
        select: { products: true },
      },
    },
    orderBy: { name: 'asc' },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Categories</h1>
          <p className="text-gray-400">Manage product categories</p>
        </div>
        <Link href="/admin/categories/new">
          <Button>
            <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clipRule="evenodd" />
            </svg>
            Add Category
          </Button>
        </Link>
      </div>

      {/* Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {categories.length === 0 && (
          <div className="col-span-full">
            <Card className="p-12 text-center">
              <p className="text-gray-400 mb-4">No categories found</p>
              <Link href="/admin/categories/new">
                <Button>Create your first category</Button>
              </Link>
            </Card>
          </div>
        )}

        {categories.map((category) => (
          <Card key={category.id} className="p-6 hover:bg-gray-800/50 transition-colors">
            {/* Category Image */}
            {category.image && (
              <div className="relative w-full h-40 bg-gray-800 rounded-lg overflow-hidden mb-4">
                <Image
                  src={category.image}
                  alt={category.name}
                  fill
                  className="object-cover"
                />
              </div>
            )}
            {!category.image && (
              <div className="w-full h-40 bg-gray-800 rounded-lg flex items-center justify-center mb-4">
                <svg className="w-16 h-16 text-gray-600" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clipRule="evenodd" />
                </svg>
              </div>
            )}

            {/* Category Info */}
            <div className="mb-4">
              <h3 className="text-xl font-bold text-white mb-1">{category.name}</h3>
              <p className="text-sm text-gray-400 mb-2">{category.slug}</p>
              {category.description && (
                <p className="text-sm text-gray-300 line-clamp-2">{category.description}</p>
              )}
            </div>

            {/* Stats */}
            <div className="flex items-center justify-between pt-4 border-t border-gray-700">
              <div className="flex items-center space-x-2 text-sm text-gray-400">
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 2a4 4 0 00-4 4v1H5a1 1 0 00-.994.89l-1 9A1 1 0 004 18h12a1 1 0 00.994-1.11l-1-9A1 1 0 0015 7h-1V6a4 4 0 00-4-4zm2 5V6a2 2 0 10-4 0v1h4zm-6 3a1 1 0 112 0 1 1 0 01-2 0zm7-1a1 1 0 100 2 1 1 0 000-2z" clipRule="evenodd" />
                </svg>
                <span>{category._count.products} products</span>
              </div>
              <div className="flex items-center space-x-2">
                <Link
                  href={`/products?category=${category.slug}`}
                  target="_blank"
                  className="text-sm text-gray-400 hover:text-white transition-colors"
                >
                  View
                </Link>
                <Link
                  href={`/admin/categories/${category.id}/edit`}
                  className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
                >
                  Edit
                </Link>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Summary */}
      <div className="flex items-center justify-between text-sm text-gray-400">
        <p>Total: {categories.length} categor{categories.length === 1 ? 'y' : 'ies'}</p>
        <p>
          Total Products: {categories.reduce((sum, cat) => sum + cat._count.products, 0)}
        </p>
      </div>
    </div>
  );
}

// Made with Bob
