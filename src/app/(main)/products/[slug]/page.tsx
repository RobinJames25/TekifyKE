import { notFound } from 'next/navigation';
import Image from 'next/image';
import Link from 'next/link';
import { ArrowLeft, Check, ShoppingCart, Truck, Shield } from 'lucide-react';
import { prisma } from '@/lib/prisma';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ProductCard } from '@/components/products/product-card';
import { formatPrice } from '@/lib/utils';
import { AddToCartButton } from '@/components/products/add-to-cart-button';
import { ProductImageCarousel } from '@/components/products/product-image-carousel';

interface ProductPageProps {
  params: Promise<{ slug: string }>;
}

async function getProduct(slug: string) {
  const product = await prisma.product.findUnique({
    where: { slug },
    include: {
      category: true,
    },
  });

  if (!product) {
    return null;
  }

  return product;
}

async function getRelatedProducts(categoryId: string, currentProductId: string) {
  const products = await prisma.product.findMany({
    where: {
      categoryId,
      id: { not: currentProductId },
      stock: { gt: 0 },
    },
    include: {
      category: true,
    },
    take: 4,
    orderBy: { createdAt: 'desc' },
  });

  return products;
}

export async function generateMetadata({ params }: ProductPageProps) {
  const { slug } = await params;
  const product = await getProduct(slug);

  if (!product) {
    return {
      title: 'Product Not Found',
    };
  }

  return {
    title: `${product.name} | TekifyKE`,
    description: product.description,
    openGraph: {
      title: product.name,
      description: product.description,
      images: product.images,
    },
  };
}

export default async function ProductPage({ params }: ProductPageProps) {
  const { slug } = await params;
  const product = await getProduct(slug);

  if (!product) {
    notFound();
  }

  const relatedProducts = await getRelatedProducts(product.categoryId, product.id);

  const isLowStock = product.stock > 0 && product.stock < 10;
  const isOutOfStock = product.stock === 0;

  // Parse attributes if they exist
  const attributes = product.attributes as Record<string, string> | null;

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back Button */}
      <Button variant="ghost" size="sm" className="mb-6" asChild>
        <Link href="/products">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Products
        </Link>
      </Button>

      <div className="grid gap-8 lg:grid-cols-2">
        {/* Product Images */}
        <div>
          <ProductImageCarousel images={product.images} name={product.name} />
        </div>

        {/* Product Info */}
        <div className="space-y-6">
          {/* Category Badge */}
          <Link
            href={`/products?category=${product.category.slug}`}
            className="inline-block rounded-full bg-primary/10 px-3 py-1 text-sm font-medium text-primary hover:bg-primary/20"
          >
            {product.category.name}
          </Link>

          {/* Product Name */}
          <h1 className="text-3xl font-bold tracking-tight lg:text-4xl">
            {product.name}
          </h1>

          {/* Price */}
          <div className="flex items-baseline gap-4">
            <p className="text-4xl font-bold">{formatPrice(product.price)}</p>
          </div>

          {/* Stock Status */}
          <div className="flex items-center gap-2">
            {isOutOfStock ? (
              <span className="flex items-center gap-2 text-destructive">
                <span className="h-2 w-2 rounded-full bg-destructive" />
                Out of Stock
              </span>
            ) : isLowStock ? (
              <span className="flex items-center gap-2 text-yellow-600">
                <span className="h-2 w-2 rounded-full bg-yellow-600" />
                Only {product.stock} left in stock
              </span>
            ) : (
              <span className="flex items-center gap-2 text-green-600">
                <Check className="h-4 w-4" />
                In Stock
              </span>
            )}
          </div>

          {/* Add to Cart */}
          <AddToCartButton
            product={{
              id: product.id,
              name: product.name,
              price: product.price,
              image: product.images[0] || '/placeholder.png',
              slug: product.slug,
            }}
            disabled={isOutOfStock}
          />

          {/* Features */}
          <div className="space-y-3 border-t pt-6">
            <div className="flex items-center gap-3 text-sm">
              <Truck className="h-5 w-5 text-primary" />
              <span>Free delivery in Nairobi within 24 hours</span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <Shield className="h-5 w-5 text-primary" />
              <span>Authentic products with warranty</span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <Check className="h-5 w-5 text-primary" />
              <span>Secure payment options</span>
            </div>
          </div>

          {/* Description */}
          <div className="border-t pt-6">
            <h2 className="mb-3 text-lg font-semibold">Description</h2>
            <p className="text-muted-foreground">{product.description}</p>
          </div>

          {/* Specifications */}
          {attributes && Object.keys(attributes).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Specifications</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="space-y-3">
                  {Object.entries(attributes).map(([key, value]) => (
                    <div
                      key={key}
                      className="flex justify-between border-b pb-3 last:border-0"
                    >
                      <dt className="font-medium capitalize">
                        {key.replace(/([A-Z])/g, ' $1').trim()}
                      </dt>
                      <dd className="text-muted-foreground">{value}</dd>
                    </div>
                  ))}
                </dl>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Related Products */}
      {relatedProducts.length > 0 && (
        <div className="mt-16">
          <div className="mb-8 flex items-center justify-between">
            <h2 className="text-2xl font-bold tracking-tight">Related Products</h2>
            <Button variant="outline" size="sm" asChild>
              <Link href={`/products?category=${product.category.slug}`}>
                View All
              </Link>
            </Button>
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {relatedProducts.map((relatedProduct) => (
              <ProductCard
                key={relatedProduct.id}
                id={relatedProduct.id}
                name={relatedProduct.name}
                slug={relatedProduct.slug}
                price={relatedProduct.price}
                image={relatedProduct.images[0] || '/placeholder.png'}
                category={relatedProduct.category.name}
                stock={relatedProduct.stock}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Made with Bob
