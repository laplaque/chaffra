import { greet } from "./utils";

export function main(): void {
    const message = greet("world");
    console.log(message);
}

function unusedHelper(): string {
    return "this is never called";
}

export class UserService {
    private name: string;

    constructor(name: string) {
        this.name = name;
    }

    public getName(): string {
        return this.name;
    }
}
