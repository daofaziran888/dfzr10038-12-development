import { createRouter, createWebHistory } from 'vue-router'

import Overview from '@/views/Overview.vue'
import CatalogLineageView from '@/views/CatalogLineageView.vue'
import WorkbenchView from '@/views/WorkbenchView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'overview', component: Overview },
    { path: '/catalog_lineage', name: 'catalog_lineage', component: CatalogLineageView },
    { path: '/:moduleKey', name: 'module', component: WorkbenchView, props: true },
  ],
})

export default router
