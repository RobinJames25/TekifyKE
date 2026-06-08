'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { Minus, Plus, Trash2, ShoppingBag, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { useCartStore } from '@/lib/store/cart-store';
import { formatPrice } from '@/lib/utils';

export default function CartPage() {
  const [mounted, setMounted] = useState(false);
  const { items, updateQuantity, removeItem, getTotalPrice, getTotalItems, clearCart } =
    useCartStore();

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="h-96 animate-pulse rounded-lg bg-muted" />
      </div>
    );
  }

  const totalPrice = getTotalPrice();
  const totalItems = getTotalItems();
  const deliveryFee = totalPrice > 50000 ? 0 : 500; // Free delivery over KES 50,000
  const finalTotal = totalPrice + deliveryFee;

  if (items.length === 0) {
    return (
      <div className="container mx-auto px-4 py-16">
        <div className="flex min-h-[60vh] flex-col items-center justify-center">
          <div className="mb-6 flex h-24 w-24 items-center justify-center rounded-full bg-muted">
            <ShoppingBag className="h-12 w-12 text-muted-foreground" />
          </div>
          <h1 className="mb-2 text-2xl font-bold">Your cart is empty</h1>
          <p className="mb-8 text-muted-foreground">
            Add some products to get started
          </p>
          <Button size="lg" asChild>
            <Link href="/products">
              Browse Products
              <ArrowRight className="ml-2 h-5 w-5" />
            </Link>
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Shopping Cart</h1>
        <p className="mt-2 text-muted-foreground">
          {totalItems} {totalItems === 1 ? 'item' : 'items'} in your cart
        </p>
      </div>

      <div className="grid gap-8 lg:grid-cols-3">
        {/* Cart Items */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Cart Items</CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearCart}
                className="text-destructive hover:text-destructive"
              >
                Clear Cart
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              {items.map((item) => (
                <div
                  key={item.id}
                  className="flex gap-4 border-b pb-4 last:border-0 last:pb-0"
                >
                  {/* Product Image */}
                  <Link
                    href={`/products/${item.slug}`}
                    className="relative h-24 w-24 flex-shrink-0 overflow-hidden rounded-lg bg-muted"
                  >
                    <Image
                      src={item.image}
                      alt={item.name}
                      fill
                      className="object-cover"
                      sizes="96px"
                    />
                  </Link>

                  {/* Product Info */}
                  <div className="flex flex-1 flex-col justify-between">
                    <div>
                      <Link
                        href={`/products/${item.slug}`}
                        className="font-semibold hover:text-primary"
                      >
                        {item.name}
                      </Link>
                      <p className="mt-1 text-lg font-bold">
                        {formatPrice(item.price)}
                      </p>
                    </div>

                    {/* Quantity Controls */}
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() =>
                            updateQuantity(item.id, Math.max(1, item.quantity - 1))
                          }
                          disabled={item.quantity <= 1}
                        >
                          <Minus className="h-4 w-4" />
                        </Button>
                        <span className="w-12 text-center font-medium">
                          {item.quantity}
                        </span>
                        <Button
                          variant="outline"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() => updateQuantity(item.id, item.quantity + 1)}
                        >
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeItem(item.id)}
                        className="text-destructive hover:text-destructive"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />
                        Remove
                      </Button>
                    </div>
                  </div>

                  {/* Item Total */}
                  <div className="text-right">
                    <p className="font-bold">
                      {formatPrice(item.price * item.quantity)}
                    </p>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Order Summary */}
        <div>
          <Card className="sticky top-4">
            <CardHeader>
              <CardTitle>Order Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Subtotal</span>
                  <span className="font-medium">{formatPrice(totalPrice)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Delivery</span>
                  <span className="font-medium">
                    {deliveryFee === 0 ? (
                      <span className="text-green-600">FREE</span>
                    ) : (
                      formatPrice(deliveryFee)
                    )}
                  </span>
                </div>
                {deliveryFee > 0 && (
                  <p className="text-xs text-muted-foreground">
                    Free delivery on orders over {formatPrice(50000)}
                  </p>
                )}
              </div>

              <div className="border-t pt-4">
                <div className="flex justify-between">
                  <span className="text-lg font-semibold">Total</span>
                  <span className="text-2xl font-bold">{formatPrice(finalTotal)}</span>
                </div>
              </div>

              <div className="space-y-2 rounded-lg bg-muted p-4 text-sm">
                <p className="font-medium">Delivery Information:</p>
                <ul className="space-y-1 text-muted-foreground">
                  <li>• Nairobi: 24 hours delivery</li>
                  <li>• Other areas: 2-3 business days</li>
                  <li>• Secure payment options</li>
                </ul>
              </div>
            </CardContent>
            <CardFooter className="flex-col gap-2">
              <Button size="lg" className="w-full" asChild>
                <Link href="/checkout">
                  Proceed to Checkout
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Link>
              </Button>
              <Button variant="outline" size="lg" className="w-full" asChild>
                <Link href="/products">Continue Shopping</Link>
              </Button>
            </CardFooter>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
