import { prisma } from '@/lib/prisma';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import Image from 'next/image';

interface ProductsPageProps {
  searchParams: Promise<{
    stock?: string;
    category?: string;
    search?: string;
  }>;
}

export const metadata = {
  title: 'Products - Admin Dashboard',
  description: 'Manage products in TekifyKE',
};

export default async function AdminProductsPage({ searchParams }: ProductsPageProps) {
  const params = await searchParams;
  const { stock, category, search } = params;

  // Build where clause
  const where: any = {};

  if (stock === 'low') {
    where.stock = { lte: 10 };
  } else if (stock === 'out') {
    where.stock = 0;
  }

  if (category) {
    where.categoryId = category;
  }

  if (search) {
    where.OR = [
      { name: { contains: search, mode: 'insensitive' } },
      { description: { contains: search, mode: 'insensitive' } },
    ];
  }

  // Fetch products
  const products = await prisma.product.findMany({
    where,
    include: {
      category: {
        select: { name: true },
      },
      _count: {
        select: { orderItems: true },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  // Fetch categories for filter
  const categories = await prisma.category.findMany({
    select: { id: true, name: true },
    orderBy: { name: 'asc' },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Products</h1>
          <p className="text-gray-400">Manage your product inventory</p>
        </div>
        <Link href="/admin/products/new">
          <Button>
            <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clipRule="evenodd" />
            </svg>
            Add Product
          </Button>
        </Link>
      </div>

      {/* Filters */}
      <Card className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div className="md:col-span-2">
            <form action="/admin/products" method="get">
              <input
                type="text"
                name="search"
                defaultValue={search}
                placeholder="Search products..."
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
              />
            </form>
          </div>

          {/* Stock Filter */}
          <div>
            <select
              name="stock"
              defaultValue={stock || ''}
              onChange={(e) => {
                const url = new URL(window.location.href);
                if (e.target.value) {
                  url.searchParams.set('stock', e.target.value);
                } else {
                  url.searchParams.delete('stock');
                }
                window.location.href = url.toString();
              }}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
            >
              <option value="">All Stock Levels</option>
              <option value="low">Low Stock (≤10)</option>
              <option value="out">Out of Stock</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <select
              name="category"
              defaultValue={category || ''}
              onChange={(e) => {
                const url = new URL(window.location.href);
                if (e.target.value) {
                  url.searchParams.set('category', e.target.value);
                } else {
                  url.searchParams.delete('category');
                }
                window.location.href = url.toString();
              }}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
            >
              <option value="">All Categories</option>
              {categories.map((cat) => (
                <option key={cat.id} value={cat.id}>
                  {cat.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Products Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-800 border-b border-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Product
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Category
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Price
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Stock
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Sales
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {products.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-gray-400">
                    No products found. <Link href="/admin/products/new" className="text-blue-400 hover:underline">Add your first product</Link>
                  </td>
                </tr>
              )}
              {products.map((product) => (
                <tr key={product.id} className="hover:bg-gray-800/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-3">
                      <div className="relative w-12 h-12 bg-gray-800 rounded-lg overflow-hidden flex-shrink-0">
                        {product.images[0] ? (
                          <Image
                            src={product.images[0]}
                            alt={product.name}
                            fill
                            className="object-cover"
                          />
                        ) : (
                          <div className="w-full h-full flex items-center justify-center text-gray-600">
                            <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clipRule="evenodd" />
                            </svg>
                          </div>
                        )}
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-white truncate max-w-xs">
                          {product.name}
                        </p>
                        <p className="text-xs text-gray-400 truncate max-w-xs">
                          {product.slug}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-gray-300">{product.category.name}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm font-medium text-white">
                      KES {product.price.toLocaleString()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`text-sm font-medium ${
                        product.stock === 0
                          ? 'text-red-500'
                          : product.stock <= 10
                          ? 'text-yellow-500'
                          : 'text-green-500'
                      }`}
                    >
                      {product.stock}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-gray-300">
                      {product._count.orderItems}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    {product.featured && (
                      <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-blue-500/10 text-blue-500">
                        Featured
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right space-x-2">
                    <Link
                      href={`/products/${product.slug}`}
                      target="_blank"
                      className="inline-flex items-center px-3 py-1 text-sm text-gray-400 hover:text-white transition-colors"
                    >
                      View
                    </Link>
                    <Link
                      href={`/admin/products/${product.id}/edit`}
                      className="inline-flex items-center px-3 py-1 text-sm text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      Edit
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Summary */}
      <div className="flex items-center justify-between text-sm text-gray-400">
        <p>Showing {products.length} product(s)</p>
        <p>
          {products.filter(p => p.stock <= 10).length} low stock •{' '}
          {products.filter(p => p.stock === 0).length} out of stock
        </p>
      </div>
    </div>
  );
}

// Made with Bob
