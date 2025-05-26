class Node:

    def __init__(self, key):

        self.key = key

        self.left = None

        self.right = None
 
 
class BinarySearchTree:

    def __init__(self):

        self.root = None
 
    # Insert a new key

    def insert(self, key):

        self.root = self._insert_recursive(self.root, key)
 
    def _insert_recursive(self, node, key):

        if node is None:

            return Node(key)

        if key < node.key:

            node.left = self._insert_recursive(node.left, key)

        elif key > node.key:

            node.right = self._insert_recursive(node.right, key)

        return node
 
    # Search for a key

    def search(self, key):

        return self._search_recursive(self.root, key)
 
    def _search_recursive(self, node, key):

        if node is None or node.key == key:

            return node

        if key < node.key:

            return self._search_recursive(node.left, key)

        return self._search_recursive(node.right, key)
 
    # Delete a key

    def delete(self, key):

        self.root = self._delete_recursive(self.root, key)
 
    def _delete_recursive(self, node, key):

        if node is None:

            return node
 
        if key < node.key:

            node.left = self._delete_recursive(node.left, key)

        elif key > node.key:

            node.right = self._delete_recursive(node.right, key)

        else:

            # Node with only one child or no child

            if node.left is None:

                return node.right

            elif node.right is None:

                return node.left
 
            # Node with two children: get the inorder successor

            temp = self._min_value_node(node.right)

            node.key = temp.key

            node.right = self._delete_recursive(node.right, temp.key)
 
        return node
 
    def _min_value_node(self, node):

        current = node

        while current.left is not None:

            current = current.left

        return current
 
    # Inorder traversal (Left, Root, Right)

    def inorder(self):

        return self._inorder_recursive(self.root)
 
    def _inorder_recursive(self, node):

        result = []

        if node:

            result = self._inorder_recursive(node.left)

            result.append(node.key)

            result += self._inorder_recursive(node.right)

        return result
