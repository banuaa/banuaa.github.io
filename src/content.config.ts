import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blog = defineCollection({
	// Load Markdown and MDX files in the `src/content/blog/` directory.
	loader: glob({ base: './src/content/blog', pattern: '**/*.{md,mdx}' }),
	// Type-check frontmatter using a schema
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string(),

			// Dates
			pubDate: z.coerce.date(),
			updatedDate: z.coerce.date().optional(),

			// Hero image (Astro image pipeline)
			heroImage: image().optional(),

			// 👇 ADD THIS (Tags support)
			tags: z
				.array(z.string().transform((t) => t.toLowerCase()))
				.optional(),
		}),
});

export const collections = { blog };