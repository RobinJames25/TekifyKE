import Link from 'next/link';
import { PackageX } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';

export default function ProductNotFound() {
  return (
    <div className="container mx-auto px-4 py-16">
      <div className="flex min-h-[60vh] items-center justify-center">
        <Card className="w-full max-w-md text-center">
          <CardHeader>
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
              <PackageX className="h-8 w-8 text-muted-foreground" />
            </div>
            <CardTitle>Product Not Found</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              The product you're looking for doesn't exist or has been removed from our
              catalog.
            </p>
          </CardContent>
          <CardFooter className="flex gap-2">
            <Button asChild className="flex-1">
              <Link href="/products">Browse Products</Link>
            </Button>
            <Button variant="outline" asChild className="flex-1">
              <Link href="/">Go Home</Link>
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

// Made with Bob
