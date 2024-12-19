                    30                                                 
                 /      \               
             5         45
           /    \            \
         2     20         50      
                /   \          / 
              12  22     48


2) print the tree as   2, 15, 22, 48 -> 20, 50 -> 5, 45 -> 30 
L1 :      2,    12,   22,   48
L2:      20,   50
L3:       5,    45
L4:       30


voif printLevel(BSTNode *root){

}

int dfs(BSTNode *root){
    if(root == nullptr)[
        return 0;
    ]
    int leftLevel = dfs(root->left);
    int rightlevl = dfs(root->right);
    reurn root->level = max(leftlevel, rightlevel)+1;
}







1)  find the nearest value of a specific key     17 —> 20.     50 —>50.    46 —> 45
#include <iostream>
using namespace std;
struct BSTNode{
    BSTNode * left, *right;
    int val;
    BSTNode(int v){
        val= v;
        left =nullptr;
        right =nullptr;
    }
};
bool check(int a, int b, int x){
    int diff1 = abs(a-x);
    int diff2= abs(b-x);
    if(diff1 != diff2){
        return diff1 < diff2;

    }
    return a>b;
}

void search(BSTNode *root, int &ans,int x){
    if(root == nullptr)
        return;
    if(check(root->val, ans,x)){
        ans = root->val;
    }

    if(ans == x)
    {
        return;
    }    
    if(root->val <= x){
        search(root->right, ans, x);
    }
    else{
        search(root->left, ans, x);
    }

}

