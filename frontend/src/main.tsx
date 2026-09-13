import React from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';
import '@tanstack/react-table';
import './style.css';

const queryClient = new QueryClient();
const fetchJson = (path: string) => fetch(path).then((response) => response.json());
function Dashboard() { const policies = useQuery({ queryKey: ['policies'], queryFn: () => fetchJson('/api/policies') }); const servers = useQuery({ queryKey: ['servers'], queryFn: () => fetchJson('/api/mcp-servers') }); return <main><h1>MCP Firewall</h1><nav><Link to="/">Dashboard</Link> <Link to="/policies">Policies</Link> <Link to="/servers">MCP Servers</Link></nav><section><h2>Policies</h2><p>{policies.data?.length ?? 0} configured</p><h2>MCP Servers</h2><p>{servers.data?.length ?? 0} configured</p></section></main>; }
function App() { return <Routes><Route path="*" element={<Dashboard />} /></Routes>; }
createRoot(document.getElementById('root')!).render(<QueryClientProvider client={queryClient}><BrowserRouter><App /></BrowserRouter></QueryClientProvider>);
