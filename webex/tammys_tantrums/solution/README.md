# Tammy's Tantrums Solution

We are given a CRUD website wherein users can create short notes called "tantrums" which are displayed inside floating bubbles. Each tantrum must have a title and a description. Users can set the tantrum as private or public. Public tantrums are exhibited on the user's public profile at `/<username>` and can be accessed by anyone. Private tantrums can only be accessed by the tantrum's creator. The flag is located in the description of a private tantrum under the `tammy` user.

Upon analyzing the provided source code, we find a possible blind mongodb injection at the delete tantrum route `src/app/api/v1/tantrums/[id]/route.ts` wherein the `tantrumId` user input is being provided to a [mongoose](https://www.npmjs.com/package/mongoose) `findOne()` call without sanitization:

```js
const whereStr = `function() { return this._id === '${tantrumId}' }`;
const tantrum = await Tantrum.findOne({
    $where: whereStr,
});
if (!tantrum) {
    return errorResponse("Request failed", "Tantrum not found", 404);
} else if (tantrum.userId !== userId) {
    return errorResponse(
        "Request failed",
        "Tantrum belongs to another user",
        403
    );
}

const response = await Tantrum.findOneAndDelete({
    $where: whereStr,
});
if (!response) {
    return errorResponse("Request failed", "Failed to delete tantrum", 500);
}
```

The route first checks whether the tantrum exists using the [`$where` operator](https://www.mongodb.com/docs/manual/reference/operator/query/where/). Then it checks if the tantrum is owned by the user that sent the deletion request. If both checks pass, the tantrum is deleted and it's `_id` is pulled from the user's `tantrums` array.

By passing in a payload like `' || this.description.startsWith("nite{") || '1337' == '` and analyzing the response status code, we can search through all the tantrums in the database, including private tantrums created by other users. We will get a `403` response if our string matches a tantrum's description and a `404` in case of no match. Brute-forcing all characters in `_{}a-zA-Z0-9` using this exploit gets us the flag.

[Solve script](solve.py)
