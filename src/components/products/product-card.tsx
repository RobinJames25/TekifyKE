import Link from 'next/link';
import Image from 'next/image';
import { ShoppingCart } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { formatPrice } from '@/lib/utils';

interface ProductCardProps {
  id: string;
  name: string;
  slug: string;
  price: number;
  image: string;
  category: string;
  stock: number;
}

export function ProductCard({
  id,
  name,
  slug,
  price,
  image,
  category,
  stock,
}: ProductCardProps) {
  const isLowStock = stock > 0 && stock < 10;
  const isOutOfStock = stock === 0;

  return (
    <Card className="group overflow-hidden transition-all hover:shadow-lg">
      <Link href={`/products/${slug}`}>
        <div className="relative aspect-square overflow-hidden bg-muted">
          <Image
            src={image}
            alt={name}
            fill
            className="object-cover transition-transform group-hover:scale-105"
            sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
          />
          {isOutOfStock && (
            <div className="absolute inset-0 flex items-center justify-center bg-background/80">
              <span className="rounded-full bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground">
                Out of Stock
              </span>
            </div>
          )}
          {isLowStock && !isOutOfStock && (
            <div className="absolute right-2 top-2 rounded-full bg-destructive px-3 py-1 text-xs font-semibold text-destructive-foreground">
              Only {stock} left
            </div>
          )}
        </div>
      </Link>
      <CardHeader>
        <Link href={`/products/${slug}`}>
          <CardTitle className="line-clamp-2 text-base transition-colors hover:text-primary">
            {name}
          </CardTitle>
        </Link>
        <p className="text-sm text-muted-foreground">{category}</p>
      </CardHeader>
      <CardContent>
        <p className="text-2xl font-bold">{formatPrice(price)}</p>
      </CardContent>
      <CardFooter className="gap-2">
        <Button
          className="flex-1"
          size="sm"
          disabled={isOutOfStock}
          asChild={!isOutOfStock}
        >
          {isOutOfStock ? (
            'Out of Stock'
          ) : (
            <Link href={`/products/${slug}`}>View Details</Link>
          )}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={isOutOfStock}
          onClick={(e) => {
            e.preventDefault();
            // Add to cart functionality will be implemented
            console.log('Add to cart:', id);
          }}
        >
          <ShoppingCart className="h-4 w-4" />
        </Button>
      </CardFooter>
    </Card>
  );
}

// Made with Bob
