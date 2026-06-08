import { Suspense } from 'react';
import { prisma } from '@/lib/prisma';
import { ProductCard } from '@/components/products/product-card';
import { ProductsFilter } from '@/components/products/products-filter';
import { Button } from '@/components/ui/button';
import { Search } from 'lucide-react';

interface SearchParams {
  category?: string;
  sort?: string;
  minPrice?: string;
  maxPrice?: string;
  inStock?: string;
  search?: string;
  page?: string;
}

interface ProductsPageProps {
  searchParams: Promise<SearchParams>;
}

const ITEMS_PER_PAGE = 12;

async function getProducts(params: SearchParams) {
  const {
    category,
    sort = 'newest',
    minPrice,
    maxPrice,
    inStock,
    search,
    page = '1',
  } = params;

  const currentPage = parseInt(page);
  const skip = (currentPage - 1) * ITEMS_PER_PAGE;

  // Build where clause
  const where: any = {};

  if (category) {
    where.category = {
      slug: category,
    };
  }

  if (minPrice || maxPrice) {
    where.price = {};
    if (minPrice) where.price.gte = parseFloat(minPrice);
    if (maxPrice) where.price.lte = parseFloat(maxPrice);
  }

  if (inStock === 'true') {
    where.stock = {
      gt: 0,
    };
  }

  if (search) {
    where.OR = [
      { name: { contains: search, mode: 'insensitive' } },
      { description: { contains: search, mode: 'insensitive' } },
    ];
  }

  // Build orderBy clause
  let orderBy: any = {};
  switch (sort) {
    case 'price-asc':
      orderBy = { price: 'asc' };
      break;
    case 'price-desc':
      orderBy = { price: 'desc' };
      break;
    case 'name-asc':
      orderBy = { name: 'asc' };
      break;
    case 'name-desc':
      orderBy = { name: 'desc' };
      break;
    case 'newest':
    default:
      orderBy = { createdAt: 'desc' };
      break;
  }

  const [products, totalCount] = await Promise.all([
    prisma.product.findMany({
      where,
      include: {
        category: true,
      },
      orderBy,
      take: ITEMS_PER_PAGE,
      skip,
    }),
    prisma.product.count({ where }),
  ]);

  const totalPages = Math.ceil(totalCount / ITEMS_PER_PAGE);

  return { products, totalCount, totalPages, currentPage };
}

async function getCategories() {
  return prisma.category.findMany({
    orderBy: { name: 'asc' },
  });
}

export default async function ProductsPage({ searchParams }: ProductsPageProps) {
  const params = await searchParams;
  const [{ products, totalCount, totalPages, currentPage }, categories] =
    await Promise.all([getProducts(params), getCategories()]);

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Products</h1>
        <p className="mt-2 text-muted-foreground">
          Browse our collection of premium electronics
        </p>
      </div>

      {/* Search Bar */}
      <div className="mb-6">
        <form action="/products" method="get" className="relative">
          <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            name="search"
            defaultValue={params.search}
            placeholder="Search products..."
            className="w-full rounded-lg border bg-background py-3 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-primary"
          />
          {/* Preserve other params */}
          {params.category && (
            <input type="hidden" name="category" value={params.category} />
          )}
          {params.sort && <input type="hidden" name="sort" value={params.sort} />}
          {params.minPrice && (
            <input type="hidden" name="minPrice" value={params.minPrice} />
          )}
          {params.maxPrice && (
            <input type="hidden" name="maxPrice" value={params.maxPrice} />
          )}
          {params.inStock && (
            <input type="hidden" name="inStock" value={params.inStock} />
          )}
        </form>
      </div>

      <div className="grid gap-8 lg:grid-cols-[280px_1fr]">
        {/* Filters Sidebar */}
        <aside>
          <ProductsFilter categories={categories} />
        </aside>

        {/* Products Grid */}
        <div>
          {/* Results Count */}
          <div className="mb-6 flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {products.length} of {totalCount} products
            </p>
          </div>

          {/* Products */}
          {products.length > 0 ? (
            <>
              <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                {products.map((product) => (
                  <ProductCard
                    key={product.id}
                    id={product.id}
                    name={product.name}
                    slug={product.slug}
                    price={product.price}
                    image={product.images[0] || '/placeholder.png'}
                    category={product.category.name}
                    stock={product.stock}
                  />
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="mt-12 flex items-center justify-center gap-2">
                  <Button
                    variant="outline"
                    disabled={currentPage === 1}
                    asChild={currentPage > 1}
                  >
                    {currentPage > 1 ? (
                      <a
                        href={`/products?${new URLSearchParams({
                          ...params,
                          page: String(currentPage - 1),
                        }).toString()}`}
                      >
                        Previous
                      </a>
                    ) : (
                      'Previous'
                    )}
                  </Button>

                  <div className="flex items-center gap-1">
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(
                      (pageNum) => {
                        // Show first page, last page, current page, and pages around current
                        const showPage =
                          pageNum === 1 ||
                          pageNum === totalPages ||
                          Math.abs(pageNum - currentPage) <= 1;

                        if (!showPage) {
                          // Show ellipsis
                          if (
                            pageNum === currentPage - 2 ||
                            pageNum === currentPage + 2
                          ) {
                            return (
                              <span key={pageNum} className="px-2">
                                ...
                              </span>
                            );
                          }
                          return null;
                        }

                        return (
                          <Button
                            key={pageNum}
                            variant={
                              pageNum === currentPage ? 'default' : 'outline'
                            }
                            size="sm"
                            asChild={pageNum !== currentPage}
                          >
                            {pageNum === currentPage ? (
                              pageNum
                            ) : (
                              <a
                                href={`/products?${new URLSearchParams({
                                  ...params,
                                  page: String(pageNum),
                                }).toString()}`}
                              >
                                {pageNum}
                              </a>
                            )}
                          </Button>
                        );
                      }
                    )}
                  </div>

                  <Button
                    variant="outline"
                    disabled={currentPage === totalPages}
                    asChild={currentPage < totalPages}
                  >
                    {currentPage < totalPages ? (
                      <a
                        href={`/products?${new URLSearchParams({
                          ...params,
                          page: String(currentPage + 1),
                        }).toString()}`}
                      >
                        Next
                      </a>
                    ) : (
                      'Next'
                    )}
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="flex min-h-[400px] flex-col items-center justify-center rounded-lg border border-dashed">
              <p className="text-lg font-semibold">No products found</p>
              <p className="mt-2 text-sm text-muted-foreground">
                Try adjusting your filters or search query
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Made with Bob
