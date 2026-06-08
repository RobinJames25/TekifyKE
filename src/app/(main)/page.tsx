import Link from 'next/link';
import Image from 'next/image';
import { ArrowRight, Truck, Shield, Headphones, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { prisma } from '@/lib/prisma';
import { formatPrice } from '@/lib/utils';

async function getFeaturedProducts() {
  const products = await prisma.product.findMany({
    where: { featured: true },
    take: 8,
    include: { category: true },
    orderBy: { createdAt: 'desc' },
  });
  return products;
}

async function getCategories() {
  const categories = await prisma.category.findMany({
    take: 5,
    orderBy: { name: 'asc' },
  });
  return categories;
}

export default async function HomePage() {
  const [featuredProducts, categories] = await Promise.all([
    getFeaturedProducts(),
    getCategories(),
  ]);

  return (
    <div className="flex flex-col">
      {/* Hero Section */}
      <section className="relative overflow-hidden bg-gradient-to-br from-primary/10 via-background to-background">
        <div className="container mx-auto px-4 py-20 md:py-32">
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-8">
            <div className="flex flex-col justify-center space-y-8">
              <div className="space-y-4">
                <h1 className="text-4xl font-bold tracking-tighter sm:text-5xl md:text-6xl lg:text-7xl">
                  Premium Tech
                  <span className="block text-primary">Delivered Fast</span>
                </h1>
                <p className="max-w-[600px] text-lg text-muted-foreground md:text-xl">
                  Shop authentic electronics with warranty. Fast delivery in Nairobi within 24
                  hours. Your trusted tech partner in Kenya.
                </p>
              </div>
              <div className="flex flex-col gap-4 sm:flex-row">
                <Button size="lg" asChild>
                  <Link href="/products">
                    Shop Now
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Link>
                </Button>
                <Button size="lg" variant="outline" asChild>
                  <Link href="/categories">Browse Categories</Link>
                </Button>
              </div>
            </div>
            <div className="relative hidden lg:block">
              <div className="absolute inset-0 bg-gradient-to-tr from-primary/20 to-transparent blur-3xl" />
              <div className="relative aspect-square">
                <Image
                  src="https://images.unsplash.com/photo-1498049794561-7780e7231661?w=800"
                  alt="Premium Electronics"
                  fill
                  className="object-cover rounded-2xl"
                  priority
                />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="border-y bg-muted/50 py-12">
        <div className="container mx-auto px-4">
          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-4">
            <div className="flex items-start space-x-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <Truck className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold">Fast Delivery</h3>
                <p className="text-sm text-muted-foreground">
                  Nairobi delivery within 24 hours
                </p>
              </div>
            </div>
            <div className="flex items-start space-x-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold">Authentic Products</h3>
                <p className="text-sm text-muted-foreground">
                  100% genuine with warranty
                </p>
              </div>
            </div>
            <div className="flex items-start space-x-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <Headphones className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold">24/7 Support</h3>
                <p className="text-sm text-muted-foreground">
                  Always here to help you
                </p>
              </div>
            </div>
            <div className="flex items-start space-x-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <Zap className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold">Best Prices</h3>
                <p className="text-sm text-muted-foreground">
                  Competitive pricing guaranteed
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Categories Section */}
      <section className="py-16">
        <div className="container mx-auto px-4">
          <div className="mb-12 text-center">
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Shop by Category
            </h2>
            <p className="mt-4 text-lg text-muted-foreground">
              Find exactly what you're looking for
            </p>
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-5">
            {categories.map((category) => (
              <Link
                key={category.id}
                href={`/products?category=${category.slug}`}
                className="group"
              >
                <Card className="overflow-hidden transition-all hover:shadow-lg">
                  <div className="relative aspect-square">
                    <Image
                      src={category.image || 'https://images.unsplash.com/photo-1498049794561-7780e7231661?w=400'}
                      alt={category.name}
                      fill
                      className="object-cover transition-transform group-hover:scale-105"
                    />
                  </div>
                  <CardHeader>
                    <CardTitle className="text-center">{category.name}</CardTitle>
                  </CardHeader>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Featured Products Section */}
      <section className="bg-muted/50 py-16">
        <div className="container mx-auto px-4">
          <div className="mb-12 flex items-center justify-between">
            <div>
              <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
                Featured Products
              </h2>
              <p className="mt-2 text-lg text-muted-foreground">
                Handpicked deals just for you
              </p>
            </div>
            <Button variant="outline" asChild>
              <Link href="/products">
                View All
                <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {featuredProducts.map((product) => (
              <Link key={product.id} href={`/products/${product.slug}`} className="group">
                <Card className="overflow-hidden transition-all hover:shadow-lg">
                  <div className="relative aspect-square">
                    <Image
                      src={product.images[0] || 'https://images.unsplash.com/photo-1498049794561-7780e7231661?w=400'}
                      alt={product.name}
                      fill
                      className="object-cover transition-transform group-hover:scale-105"
                    />
                    {product.stock < 10 && product.stock > 0 && (
                      <div className="absolute right-2 top-2 rounded-full bg-destructive px-2 py-1 text-xs font-semibold text-destructive-foreground">
                        Only {product.stock} left
                      </div>
                    )}
                  </div>
                  <CardHeader>
                    <CardTitle className="line-clamp-2 text-base">
                      {product.name}
                    </CardTitle>
                    <p className="text-sm text-muted-foreground">
                      {product.category.name}
                    </p>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{formatPrice(product.price)}</p>
                  </CardContent>
                  <CardFooter>
                    <Button className="w-full" size="sm">
                      View Details
                    </Button>
                  </CardFooter>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <Card className="overflow-hidden bg-gradient-to-br from-primary/10 to-primary/5">
            <CardContent className="p-12 text-center">
              <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
                Ready to upgrade your tech?
              </h2>
              <p className="mx-auto mt-4 max-w-2xl text-lg text-muted-foreground">
                Join thousands of satisfied customers who trust TekifyKE for their electronics
                needs. Shop now and experience the difference.
              </p>
              <div className="mt-8 flex flex-col gap-4 sm:flex-row sm:justify-center">
                <Button size="lg" asChild>
                  <Link href="/products">Start Shopping</Link>
                </Button>
                <Button size="lg" variant="outline" asChild>
                  <Link href="/contact">Contact Us</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}

// Made with Bob
