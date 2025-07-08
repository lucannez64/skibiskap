import { get, writable } from 'svelte/store';
import { type Client, type ClientEx } from '$lib/decoder';

export const clientex = writable<ClientEx | undefined>(undefined);
export const client = writable<Client | undefined>(undefined);
export const token = writable<string | undefined>(undefined);

client.subscribe((c) => {
	if (c) {
		const clienteee = get(clientex);
		if (!clienteee) return;
		const nbw: ClientEx = {
			c: c,
			id: clienteee.id!
		};
		clientex.set(nbw);
	}
});

export const stores = {
	clientex
};
