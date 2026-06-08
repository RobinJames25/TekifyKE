'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useState, useTransition } from 'react';
import { X, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface Category {
  id: string;
  name: string;
  slug: string;
}

interface ProductsFilterProps {
  categories: Category[];
}

export function ProductsFilter({ categories }: ProductsFilterProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isPending, startTransition] = useTransition();
  const [showMobileFilters, setShowMobileFilters] = useState(false);

  const selectedCategory = searchParams.get('category');
  const selectedSort = searchParams.get('sort') || 'newest';
  const minPrice = searchParams.get('minPrice');
  const maxPrice = searchParams.get('maxPrice');
  const inStock = searchParams.get('inStock');

  const updateFilters = (key: string, value: string | null) => {
    const params = new URLSearchParams(searchParams.toString());
    
    if (value) {
      params.set(key, value);
    } else {
      params.delete(key);
    }
    
    // Reset to page 1 when filters change
    params.delete('page');
    
    startTransition(() => {
      router.push(`/products?${params.toString()}`);
    });
  };

  const clearFilters = () => {
    startTransition(() => {
      router.push('/products');
    });
  };

  const hasActiveFilters = selectedCategory || minPrice || maxPrice || inStock;

  const FilterContent = () => (
    <>
      {/* Categories */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold">Categories</h3>
          {selectedCategory && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => updateFilters('category', null)}
            >
              Clear
            </Button>
          )}
        </div>
        <div className="space-y-2">
          {categories.map((category) => (
            <button
              key={category.id}
              onClick={() =>
                updateFilters(
                  'category',
                  selectedCategory === category.slug ? null : category.slug
                )
              }
              className={cn(
                'w-full rounded-lg px-3 py-2 text-left text-sm transition-colors',
                selectedCategory === category.slug
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-accent'
              )}
              disabled={isPending}
            >
              {category.name}
            </button>
          ))}
        </div>
      </div>

      {/* Price Range */}
      <div className="space-y-4">
        <h3 className="font-semibold">Price Range (KES)</h3>
        <div className="space-y-2">
          <input
            type="number"
            placeholder="Min"
            value={minPrice || ''}
            onChange={(e) => updateFilters('minPrice', e.target.value || null)}
            className="w-full rounded-lg border bg-background px-3 py-2 text-sm"
            disabled={isPending}
          />
          <input
            type="number"
            placeholder="Max"
            value={maxPrice || ''}
            onChange={(e) => updateFilters('maxPrice', e.target.value || null)}
            className="w-full rounded-lg border bg-background px-3 py-2 text-sm"
            disabled={isPending}
          />
        </div>
      </div>

      {/* Availability */}
      <div className="space-y-4">
        <h3 className="font-semibold">Availability</h3>
        <label className="flex items-center space-x-2">
          <input
            type="checkbox"
            checked={inStock === 'true'}
            onChange={(e) =>
              updateFilters('inStock', e.target.checked ? 'true' : null)
            }
            className="h-4 w-4 rounded border-gray-300"
            disabled={isPending}
          />
          <span className="text-sm">In Stock Only</span>
        </label>
      </div>

      {/* Sort */}
      <div className="space-y-4">
        <h3 className="font-semibold">Sort By</h3>
        <select
          value={selectedSort}
          onChange={(e) => updateFilters('sort', e.target.value)}
          className="w-full rounded-lg border bg-background px-3 py-2 text-sm"
          disabled={isPending}
        >
          <option value="newest">Newest First</option>
          <option value="price-asc">Price: Low to High</option>
          <option value="price-desc">Price: High to Low</option>
          <option value="name-asc">Name: A to Z</option>
          <option value="name-desc">Name: Z to A</option>
        </select>
      </div>

      {/* Clear All */}
      {hasActiveFilters && (
        <Button
          variant="outline"
          className="w-full"
          onClick={clearFilters}
          disabled={isPending}
        >
          <X className="mr-2 h-4 w-4" />
          Clear All Filters
        </Button>
      )}
    </>
  );

  return (
    <>
      {/* Mobile Filter Button */}
      <div className="lg:hidden">
        <Button
          variant="outline"
          className="w-full"
          onClick={() => setShowMobileFilters(true)}
        >
          <SlidersHorizontal className="mr-2 h-4 w-4" />
          Filters
          {hasActiveFilters && (
            <span className="ml-2 rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground">
              Active
            </span>
          )}
        </Button>
      </div>

      {/* Desktop Filters */}
      <Card className="hidden lg:block">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <FilterContent />
        </CardContent>
      </Card>

      {/* Mobile Filters Overlay */}
      {showMobileFilters && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="absolute inset-0 bg-background/80 backdrop-blur-sm"
            onClick={() => setShowMobileFilters(false)}
          />
          <div className="absolute inset-y-0 right-0 w-full max-w-sm bg-background p-6 shadow-lg">
            <div className="mb-6 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Filters</h2>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setShowMobileFilters(false)}
              >
                <X className="h-5 w-5" />
              </Button>
            </div>
            <div className="space-y-6 overflow-y-auto">
              <FilterContent />
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// Made with Bob
