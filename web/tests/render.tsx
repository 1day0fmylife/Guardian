import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createMemoryHistory, createRootRoute, createRouter } from '@tanstack/react-router'

/** Server-renders a page inside a memory router so <Link> works in tests. */
export async function renderWithRouter(client: QueryClient, page: () => React.ReactNode) {
  const router = createRouter({ routeTree: createRootRoute({ component: () => <>{page()}</> }), history: createMemoryHistory({ initialEntries: ['/'] }) })
  await router.load()
  return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>)
}
