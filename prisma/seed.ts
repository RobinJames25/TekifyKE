import { PrismaClient, Role } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create admin user
  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@tekifyke.com' },
    update: {},
    create: {
      email: 'admin@tekifyke.com',
      name: 'Admin User',
      role: Role.ADMIN,
      clerkId: 'clerk_admin_seed_id',
    },
  });

  console.log('✅ Admin user created:', adminUser.email);

  // Create categories
  const categories = [
    {
      name: 'Laptops',
      slug: 'laptops',
      description: 'High-performance laptops for work and gaming',
      image: 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=800',
    },
    {
      name: 'Smartphones',
      slug: 'smartphones',
      description: 'Latest flagship smartphones',
      image: 'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=800',
    },
    {
      name: 'Audio',
      slug: 'audio',
      description: 'Premium headphones and speakers',
      image: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=800',
    },
    {
      name: 'Tablets',
      slug: 'tablets',
      description: 'Powerful tablets for productivity',
      image: 'https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=800',
    },
    {
      name: 'Accessories',
      slug: 'accessories',
      description: 'Essential tech accessories',
      image: 'https://images.unsplash.com/photo-1625948515291-69613efd103f?w=800',
    },
  ];

  const createdCategories = await Promise.all(
    categories.map((category) =>
      prisma.category.upsert({
        where: { slug: category.slug },
        update: {},
        create: category,
      })
    )
  );

  console.log('✅ Categories created:', createdCategories.length);

  // Create products
  const laptopsCategory = createdCategories.find((c) => c.slug === 'laptops')!;
  const smartphonesCategory = createdCategories.find((c) => c.slug === 'smartphones')!;
  const audioCategory = createdCategories.find((c) => c.slug === 'audio')!;
  const tabletsCategory = createdCategories.find((c) => c.slug === 'tablets')!;
  const accessoriesCategory = createdCategories.find((c) => c.slug === 'accessories')!;

  const products = [
    // Laptops
    {
      name: 'Apple MacBook Pro 16" M3 Max',
      slug: 'macbook-pro-16-m3-max',
      description:
        'The most powerful MacBook Pro ever. With the M3 Max chip, up to 128GB unified memory, and stunning Liquid Retina XDR display.',
      price: 389999,
      stock: 15,
      featured: true,
      categoryId: laptopsCategory.id,
      images: [
        'https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=800',
        'https://images.unsplash.com/photo-1611186871348-b1ce696e52c9?w=800',
      ],
      attributes: {
        processor: 'Apple M3 Max',
        ram: '48GB Unified Memory',
        storage: '1TB SSD',
        display: '16.2-inch Liquid Retina XDR',
        graphics: 'Integrated 40-core GPU',
        battery: 'Up to 22 hours',
        weight: '2.15 kg',
        ports: '3x Thunderbolt 4, HDMI, SD card slot',
      },
    },
    {
      name: 'Dell XPS 15 9530',
      slug: 'dell-xps-15-9530',
      description:
        'Premium Windows laptop with stunning OLED display, Intel 13th Gen processors, and NVIDIA RTX graphics.',
      price: 279999,
      stock: 20,
      featured: true,
      categoryId: laptopsCategory.id,
      images: [
        'https://images.unsplash.com/photo-1593642632823-8f785ba67e45?w=800',
        'https://images.unsplash.com/photo-1588872657578-7efd1f1555ed?w=800',
      ],
      attributes: {
        processor: 'Intel Core i7-13700H',
        ram: '32GB DDR5',
        storage: '1TB NVMe SSD',
        display: '15.6-inch 3.5K OLED Touch',
        graphics: 'NVIDIA RTX 4060 8GB',
        battery: 'Up to 13 hours',
        weight: '1.86 kg',
        ports: '2x Thunderbolt 4, USB-C, SD card',
      },
    },
    {
      name: 'Lenovo ThinkPad X1 Carbon Gen 11',
      slug: 'lenovo-thinkpad-x1-carbon-gen-11',
      description:
        'Business ultrabook with legendary ThinkPad durability, Intel vPro, and all-day battery life.',
      price: 249999,
      stock: 12,
      featured: false,
      categoryId: laptopsCategory.id,
      images: [
        'https://images.unsplash.com/photo-1588872657578-7efd1f1555ed?w=800',
      ],
      attributes: {
        processor: 'Intel Core i7-1365U vPro',
        ram: '16GB LPDDR5',
        storage: '512GB SSD',
        display: '14-inch 2.8K OLED',
        graphics: 'Intel Iris Xe',
        battery: 'Up to 19 hours',
        weight: '1.12 kg',
        ports: '2x Thunderbolt 4, 2x USB-A, HDMI',
      },
    },

    // Smartphones
    {
      name: 'Samsung Galaxy S24 Ultra',
      slug: 'samsung-galaxy-s24-ultra',
      description:
        'Ultimate flagship with S Pen, 200MP camera, Snapdragon 8 Gen 3, and Galaxy AI features.',
      price: 169999,
      stock: 30,
      featured: true,
      categoryId: smartphonesCategory.id,
      images: [
        'https://images.unsplash.com/photo-1610945415295-d9bbf067e59c?w=800',
        'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=800',
      ],
      attributes: {
        processor: 'Snapdragon 8 Gen 3',
        ram: '12GB',
        storage: '512GB',
        display: '6.8-inch Dynamic AMOLED 2X, 120Hz',
        camera: '200MP + 50MP + 12MP + 10MP',
        battery: '5000mAh, 45W fast charging',
        os: 'Android 14, One UI 6.1',
        features: 'S Pen, IP68, Gorilla Armor',
      },
    },
    {
      name: 'iPhone 15 Pro Max',
      slug: 'iphone-15-pro-max',
      description:
        'Titanium design, A17 Pro chip, advanced camera system with 5x optical zoom, and Action button.',
      price: 179999,
      stock: 25,
      featured: true,
      categoryId: smartphonesCategory.id,
      images: [
        'https://images.unsplash.com/photo-1592286927505-b0c2e0a13e60?w=800',
        'https://images.unsplash.com/photo-1556656793-08538906a9f8?w=800',
      ],
      attributes: {
        processor: 'A17 Pro',
        ram: '8GB',
        storage: '512GB',
        display: '6.7-inch Super Retina XDR, ProMotion',
        camera: '48MP Main + 12MP Ultra Wide + 12MP Telephoto (5x)',
        battery: 'Up to 29 hours video playback',
        os: 'iOS 17',
        features: 'Titanium, Action button, USB-C',
      },
    },
    {
      name: 'Google Pixel 8 Pro',
      slug: 'google-pixel-8-pro',
      description:
        'Pure Android experience with Google Tensor G3, exceptional AI photography, and 7 years of updates.',
      price: 139999,
      stock: 18,
      featured: false,
      categoryId: smartphonesCategory.id,
      images: [
        'https://images.unsplash.com/photo-1598327105666-5b89351aff97?w=800',
      ],
      attributes: {
        processor: 'Google Tensor G3',
        ram: '12GB',
        storage: '256GB',
        display: '6.7-inch LTPO OLED, 120Hz',
        camera: '50MP + 48MP + 48MP',
        battery: '5050mAh, 30W fast charging',
        os: 'Android 14',
        features: 'Magic Eraser, Best Take, 7 years updates',
      },
    },

    // Audio
    {
      name: 'Sony WH-1000XM5',
      slug: 'sony-wh-1000xm5',
      description:
        'Industry-leading noise cancellation, exceptional sound quality, and 30-hour battery life.',
      price: 44999,
      stock: 40,
      featured: true,
      categoryId: audioCategory.id,
      images: [
        'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=800',
        'https://images.unsplash.com/photo-1484704849700-f032a568e944?w=800',
      ],
      attributes: {
        type: 'Over-ear wireless',
        driver: '30mm',
        noiseCancellation: 'Industry-leading ANC',
        battery: '30 hours with ANC',
        connectivity: 'Bluetooth 5.2, LDAC, multipoint',
        features: 'Speak-to-Chat, Adaptive Sound Control',
        weight: '250g',
      },
    },
    {
      name: 'Apple AirPods Pro (2nd Gen)',
      slug: 'airpods-pro-2nd-gen',
      description:
        'Active Noise Cancellation, Adaptive Audio, and personalized spatial audio with dynamic head tracking.',
      price: 34999,
      stock: 50,
      featured: true,
      categoryId: audioCategory.id,
      images: [
        'https://images.unsplash.com/photo-1606841837239-c5a1a4a07af7?w=800',
      ],
      attributes: {
        type: 'In-ear wireless',
        driver: 'Custom high-excursion',
        noiseCancellation: 'Active Noise Cancellation',
        battery: '6 hours (ANC on), 30 hours with case',
        connectivity: 'Bluetooth 5.3, H2 chip',
        features: 'Adaptive Audio, Transparency mode, Find My',
        weight: '5.3g per earbud',
      },
    },
    {
      name: 'Bose QuietComfort Ultra Earbuds',
      slug: 'bose-qc-ultra-earbuds',
      description:
        'World-class noise cancellation in a compact design with Immersive Audio and all-day comfort.',
      price: 39999,
      stock: 35,
      featured: false,
      categoryId: audioCategory.id,
      images: [
        'https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=800',
      ],
      attributes: {
        type: 'In-ear wireless',
        driver: '9.3mm',
        noiseCancellation: 'World-class ANC',
        battery: '6 hours, 24 hours with case',
        connectivity: 'Bluetooth 5.3, multipoint',
        features: 'Immersive Audio, CustomTune, IPX4',
        weight: '6.24g per earbud',
      },
    },

    // Tablets
    {
      name: 'iPad Pro 12.9" M2',
      slug: 'ipad-pro-12-9-m2',
      description:
        'Ultimate iPad experience with M2 chip, Liquid Retina XDR display, and Apple Pencil hover.',
      price: 159999,
      stock: 15,
      featured: true,
      categoryId: tabletsCategory.id,
      images: [
        'https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=800',
        'https://images.unsplash.com/photo-1585790050230-5dd28404f1e9?w=800',
      ],
      attributes: {
        processor: 'Apple M2',
        ram: '8GB',
        storage: '512GB',
        display: '12.9-inch Liquid Retina XDR, ProMotion',
        camera: '12MP Wide + 10MP Ultra Wide',
        battery: 'Up to 10 hours',
        connectivity: 'Wi-Fi 6E, 5G optional',
        features: 'Face ID, Apple Pencil hover, Magic Keyboard support',
      },
    },
    {
      name: 'Samsung Galaxy Tab S9 Ultra',
      slug: 'samsung-galaxy-tab-s9-ultra',
      description:
        'Massive 14.6" AMOLED display, Snapdragon 8 Gen 2, and included S Pen for ultimate productivity.',
      price: 149999,
      stock: 10,
      featured: false,
      categoryId: tabletsCategory.id,
      images: [
        'https://images.unsplash.com/photo-1561154464-82e9adf32764?w=800',
      ],
      attributes: {
        processor: 'Snapdragon 8 Gen 2',
        ram: '12GB',
        storage: '512GB',
        display: '14.6-inch Dynamic AMOLED 2X, 120Hz',
        camera: '13MP + 8MP Ultra Wide',
        battery: '11200mAh, 45W fast charging',
        connectivity: 'Wi-Fi 6E, 5G optional',
        features: 'S Pen included, IP68, DeX mode',
      },
    },

    // Accessories
    {
      name: 'Anker 747 PowerBank 25600mAh',
      slug: 'anker-747-powerbank',
      description:
        'Ultra-high capacity power bank with 140W output, perfect for laptops and multiple devices.',
      price: 19999,
      stock: 60,
      featured: false,
      categoryId: accessoriesCategory.id,
      images: [
        'https://images.unsplash.com/photo-1609091839311-d5365f9ff1c5?w=800',
      ],
      attributes: {
        capacity: '25600mAh (92.16Wh)',
        output: '140W USB-C PD 3.1',
        ports: '2x USB-C, 1x USB-A',
        charging: '170W input for fast recharge',
        features: 'Smart display, ActiveShield 2.0',
        weight: '635g',
      },
    },
    {
      name: 'Logitech MX Master 3S',
      slug: 'logitech-mx-master-3s',
      description:
        'Premium wireless mouse with 8K DPI sensor, quiet clicks, and multi-device connectivity.',
      price: 14999,
      stock: 45,
      featured: false,
      categoryId: accessoriesCategory.id,
      images: [
        'https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=800',
      ],
      attributes: {
        sensor: '8000 DPI',
        connectivity: 'Bluetooth, USB receiver',
        battery: 'Up to 70 days',
        buttons: '7 programmable buttons',
        features: 'MagSpeed scroll, multi-device, Flow',
        weight: '141g',
      },
    },
    {
      name: 'Apple Magic Keyboard',
      slug: 'apple-magic-keyboard',
      description:
        'Wireless keyboard with scissor mechanism, rechargeable battery, and seamless Mac integration.',
      price: 12999,
      stock: 50,
      featured: false,
      categoryId: accessoriesCategory.id,
      images: [
        'https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=800',
      ],
      attributes: {
        type: 'Wireless keyboard',
        layout: 'Full-size with numeric keypad',
        connectivity: 'Bluetooth',
        battery: 'Rechargeable, 1 month per charge',
        compatibility: 'Mac, iPad, iPhone',
        features: 'Scissor mechanism, Touch ID optional',
      },
    },
  ];

  const createdProducts = await Promise.all(
    products.map((product) =>
      prisma.product.upsert({
        where: { slug: product.slug },
        update: {},
        create: product,
      })
    )
  );

  console.log('✅ Products created:', createdProducts.length);
  console.log('🎉 Database seeding completed successfully!');
}

main()
  .catch((e) => {
    console.error('❌ Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

// Made with Bob
