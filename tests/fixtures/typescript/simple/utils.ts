export function greet(name: string): string {
    return `Hello, ${name}!`;
}

export function formatDate(date: Date): string {
    return date.toISOString();
}

function internalHelper(): void {
    // not exported, not used externally
}
