'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function NewProductPage() {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setIsSubmitting(true);
    setError('');

    const formData = new FormData(e.currentTarget);
    
    // Parse images (comma-separated URLs)
    const imagesString = formData.get('images') as string;
    const images = imagesString.split(',').map(url => url.trim()).filter(Boolean);

    // Parse attributes JSON
    let attributes = null;
    const attributesString = formData.get('attributes') as string;
    if (attributesString.trim()) {
      try {
        attributes = JSON.parse(attributesString);
      } catch (err) {
        setError('Invalid JSON in attributes field');
        setIsSubmitting(false);
        return;
      }
    }

    const productData = {
      name: formData.get('name'),
      slug: formData.get('slug'),
      description: formData.get('description'),
      price: parseFloat(formData.get('price') as string),
      stock: parseInt(formData.get('stock') as string),
      categoryId: formData.get('categoryId'),
      images,
      attributes,
      featured: formData.get('featured') === 'on',
    };

    try {
      const response = await fetch('/api/admin/products', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(productData),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create product');
      }

      router.push('/admin/products');
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create product');
      setIsSubmitting(false);
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Add New Product</h1>
          <p className="text-gray-400">Create a new product in your inventory</p>
        </div>
        <Link href="/admin/products">
          <Button variant="outline">Cancel</Button>
        </Link>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSubmit}>
        <Card className="p-6 space-y-6">
          {/* Basic Information */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Basic Information</h2>
            <div className="space-y-4">
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-300 mb-2">
                  Product Name *
                </label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  required
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  placeholder="Apple MacBook Pro M3"
                />
              </div>

              <div>
                <label htmlFor="slug" className="block text-sm font-medium text-gray-300 mb-2">
                  Slug * <span className="text-gray-500">(URL-friendly name)</span>
                </label>
                <input
                  type="text"
                  id="slug"
                  name="slug"
                  required
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  placeholder="apple-macbook-pro-m3"
                />
              </div>

              <div>
                <label htmlFor="description" className="block text-sm font-medium text-gray-300 mb-2">
                  Description *
                </label>
                <textarea
                  id="description"
                  name="description"
                  required
                  rows={4}
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  placeholder="Detailed product description..."
                />
              </div>
            </div>
          </div>

          {/* Pricing & Inventory */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Pricing & Inventory</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="price" className="block text-sm font-medium text-gray-300 mb-2">
                  Price (KES) *
                </label>
                <input
                  type="number"
                  id="price"
                  name="price"
                  required
                  min="0"
                  step="0.01"
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  placeholder="150000"
                />
              </div>

              <div>
                <label htmlFor="stock" className="block text-sm font-medium text-gray-300 mb-2">
                  Stock Quantity *
                </label>
                <input
                  type="number"
                  id="stock"
                  name="stock"
                  required
                  min="0"
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  placeholder="50"
                />
              </div>
            </div>
          </div>

          {/* Category */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Category</h2>
            <div>
              <label htmlFor="categoryId" className="block text-sm font-medium text-gray-300 mb-2">
                Category *
              </label>
              <select
                id="categoryId"
                name="categoryId"
                required
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
              >
                <option value="">Select a category</option>
                {/* Categories will be loaded dynamically */}
              </select>
              <p className="mt-2 text-sm text-gray-400">
                Don't see your category? <Link href="/admin/categories" className="text-blue-400 hover:underline">Create one first</Link>
              </p>
            </div>
          </div>

          {/* Images */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Images</h2>
            <div>
              <label htmlFor="images" className="block text-sm font-medium text-gray-300 mb-2">
                Image URLs * <span className="text-gray-500">(comma-separated)</span>
              </label>
              <textarea
                id="images"
                name="images"
                required
                rows={3}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                placeholder="https://example.com/image1.jpg, https://example.com/image2.jpg"
              />
              <p className="mt-2 text-sm text-gray-400">
                Enter image URLs separated by commas. First image will be the main product image.
              </p>
            </div>
          </div>

          {/* Attributes */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Technical Specifications</h2>
            <div>
              <label htmlFor="attributes" className="block text-sm font-medium text-gray-300 mb-2">
                Attributes (JSON) <span className="text-gray-500">(optional)</span>
              </label>
              <textarea
                id="attributes"
                name="attributes"
                rows={6}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white font-mono text-sm"
                placeholder={`{
  "Processor": "Apple M3 Pro",
  "RAM": "16GB",
  "Storage": "512GB SSD",
  "Display": "14-inch Liquid Retina XDR",
  "Graphics": "18-core GPU"
}`}
              />
              <p className="mt-2 text-sm text-gray-400">
                Enter product specifications as JSON. This will be displayed on the product detail page.
              </p>
            </div>
          </div>

          {/* Options */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Options</h2>
            <div className="flex items-center">
              <input
                type="checkbox"
                id="featured"
                name="featured"
                className="w-4 h-4 text-blue-600 bg-gray-800 border-gray-700 rounded focus:ring-blue-500"
              />
              <label htmlFor="featured" className="ml-2 text-sm text-gray-300">
                Feature this product on the homepage
              </label>
            </div>
          </div>

          {/* Submit Button */}
          <div className="flex items-center justify-end space-x-4 pt-6 border-t border-gray-700">
            <Link href="/admin/products">
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </Link>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <span className="flex items-center">
                  <svg
                    className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                  Creating...
                </span>
              ) : (
                'Create Product'
              )}
            </Button>
          </div>
        </Card>
      </form>
    </div>
  );
}

// Made with Bob
