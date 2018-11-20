# Challenge 2

Ce challenge propose un service de signature d’un message avec un algorithme de signature post-quantique non spécifié. Comme dans la première épreuve, des fautes sont parfois introduites lors de la signature, à un moment non défini. Les signatures générées sont relativement grosses : 33584 octets. Les binaires signant et vérifiant les signatures sont mis à disposition des attaquants.

## Identification de l’algorithme

Un binaire de signature et un binaire de vérification sont disponibles, ainsi que la clé publique utilisée. Les signatures générées par le serveur sont bien vérifiées si on utilise la clé publique avec le binaire de vérification.

Les binaires sont des ELF 64 bits non strippés :

```shell
custom_algo_sign:       ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=dd414f75f30f315f710d4838568b65122bdcfb15, not stripped

custom_algo_verify:     ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d49f8dcab4e18d1edc51eebb8427b208bbe68830, not stripped
```

Voici un extrait de la liste des fonctions du binaire :

```
porsgensk
porssign
pruorstgenpk
sortsubset
octopruorstsign
octopruorstextract
octopruorstloadsign
octopruorstsigncmp
porsrandsubset
randombytes
cryptosignkeypair
cryptosign
...
```


Une recherche Google sur ces noms de fonction ne donne pas grand-chose. Si on sépare correctement les mots de chaque nom de fonction (« porsrandsubset » → « pors rand subset ») on retrouve dans les premiers résultats un dépôt GitHub de Kudelski : <https://github.com/gravity-postquantum/gravity-sphincs/>. Une comparaison du code source avec le binaire montre qu’il s’agit du même algorithme et de la même implémentation, seuls les noms de fonction ayant été renommés.


L’algorithme utilisé est donc Gravity-SPHINCS, un algorithme de signature stateless reposant sur des fonctions de hachage, créée par Jean-Philippe Aumasson et Guillaume Endignoux qui travaillaient alors tous deux à Kudelski. Il est dérivé de SPHINCS [TODO REF]. Nous recommandons chaudement la lecture de [<https://gendignoux.com/assets/pdf/2017-07-master-thesis-endignoux-report.pdf>] ou la lecture d’implémentations simples de l’algorithme, comme proposé dans [<https://eprint.iacr.org/2017/933.pdf>], pour comprendre le fonctionnement de l’algorithme. Seuls les mécanismes nécessaires d’être étudiés pour résoudre le challenge seront détaillés ici.


Nous avons recompilé le binaire à partir des sources du dépôt afin de valider les signatures du serveur et confirmer notre hypothèse. Cela n’a pas fonctionné. Gravity-SPHINCS est paramétrable, comme on peut le voir dans le [Makefile](https://github.com/gravity-postquantum/gravity-sphincs/blob/master/Reference_Implementation/Makefile) :


```makefile
VERSION_S= -DPORS_k=24 -DMERKLE_h=5  -DGRAVITY_d=1  -DGRAVITY_c=10
VERSION_M= -DPORS_k=32 -DMERKLE_h=5  -DGRAVITY_d=7  -DGRAVITY_c=15
VERSION_L= -DPORS_k=28 -DMERKLE_h=5  -DGRAVITY_d=10 -DGRAVITY_c=14
```

 Les paramètres utilisés dans le challenge se retrouvent rapidement par rétroconception :


```makefile
VERSION_CTF = -DPORS_k=32 -DMERKLE_h=5  -DGRAVITY_d=7 -DGRAVITY_c=0
```

 Les signatures sont correctement vérifiées. La taille des signatures générées est identique à celle des signatures générées par le serveur. La première étape est terminée.


## Fautes dans Gravity-SPHINCS

Les signatures Gravity-SPHINCS sont composées de quatre parties :


```c
struct gravity_sign {
    struct hash rand;                            /* offset 0-0x20 */
    struct octoporst_sign op_sign;               /* offset 0x20-0x4430 */ 
    struct merkle_sign merkle[GRAVITY_d];        /* offset 0x4430-0x8330 */
#if GRAVITY_c > 0
    struct hash auth[GRAVITY_c];
#endif
};
```

 Dans notre cas,  `GRAVITY_c` vaut 0 donc seuls les champs `rand`, `op_sign` et `merkle` sont présents.

La structure merkle_sign est :

```c
struct merkle_sign {
  struct wots_sign wots;                   /* 67 * 32 */
  struct hash auth[MERKLE_h];              /* 5 * 32 */
};
```


Maintenant que nous connaissons la structure des signatures Gravity-SPHINCS, nous pouvons découper celles retournées par le serveur et identifier à quel endroit la faute se produit. En comparant les signatures générées pour un même message, on s’aperçoit que la première différence se trouve toujours dans le champ « auth » de la structure merkle_sign. L’analyse du code source montre que ce champ est calculé par la fonction merkle_gen_auth. Voyons ce que nous pouvons tirer de cela.


La structure merkle_sign contient une liste de signatures WOTS et un chemin d’authentification de Merkle.

### WOTS

Le Wintermintz one-time signature scheme a été proposé par Merkle en 1989. Ce schéma est très simple. Pour signer des messages de taille $n$ bits, on choisit deux paramètres $l$ et $w$ tels que $l \cdot \log_2(w)=n$. La clé secrète est composée de $l$ chaînes de $n$ bits $(s_1, \ldots, s_l)$. La clé publique est calculée en appliquant $w-1$ fois une one-way function sur chaque chaîne de la clé secrète : $(F^{w-1}(s_1),\ldots,F^{w-1}(s_l))$.


Pour signer un message $m$ de $n$ bits, on le décompose en $l$ éléments de $log_2(w)$ bits $(x_1,\ldots,x_l)$ et on applique $x_i$ fois $F$ à chaque élément de la clé secrète. La signature est alors : $(F^{x_1}(s_1),\ldots,F^{x_l}(s_l))$.


La vérification de signature consiste à appliquer $w-1-x_i$ fois $F$ à chaque élément de la signature et à vérifier qu’il est bien égal à l’élément de la clé publique correspondant.


Dans ces conditions, un attaquant peut signer n’importe quel message avec un $x_{i'}>x_i$ : il suffit pour d’appliquer $F$ à $x_i$  $(x_{i’} - x_i)$ fois. Pour empêcher cela, un checksum est ajouté au message à signer : $C(x) = \sum_{i=1}^{l}(w-1-x_i)$. Ce checksum est lui-même signé. Le message signé est en réalité $x'=x\Vert C(x)$. Si on remplace un des $x_i$ par $x_{i’}$ avec $x_{i’} > x_i$, la valeur du checksum va diminuer, et il ne sera plus possible de le signer.


Dans Gravity-SPHINCS, la fonction one-way est Haraka-v2-256 [<https://eprint.iacr.org/2016/098>], $n$ vaut 256, $l$ vaut 64 et $w$ vaut 16. Le checksum nécessite 3 mots de $\log_2(w)$ bits pour être encodé. Les clés secrètes WOTS sont donc composées de 64 + 3 chaînes de caractères de 256 bits, chaque chaîne signant 4 bits du message.

### Merkle tree

Les arbres de Merkle sont des arbres binaires de taille *h* et dont la valeur de chaque nœud $a$ est dans $\{0, 1\}^n$ et dépend de celle de ses fils $b$ et $c$ :  $a = H(b \Vert c)$, où $H$ est une fonction de hachage de $\{0,1\}^{2n} \rightarrow \{0,1\}^n$.


Cette construction va être utilisée pour construire un schéma de signature permettant de signer de nombreux messages à partir des signatures WOTS précédemment détaillées. Pour cela, on construit un arbre de hauteur $h​$ dont chaque feuille est une clé publique WOTS. La clé publique du Merkle tree est la valeur de la racine de l’arbre.


Pour signer un message pour un index $i$ de l’arbre, on signe ce message avec la ième instance WOTS et on publie cette signature avec le chemin d’authentification. Ce chemin permet de vérifier la clé publique WOTS utilisée. Si on trace un chemin entre la ième feuille et le nœud racine, le chemin d’authentification est composé de tous les voisins des nœuds de ce chemin. Ils permettent de remonter jusqu’au nœud racine et de comparer sa valeur à celle publiée.

[TODO Schéma]


Plusieurs Merkle trees sont utilisés dans Gravity-SPHINCS. Ils forment un hyper-arbre, chaque nœud de cet arbre étant un arbre de Merkle. La clé publique de l’hyper-arbre est la clé publique de l’arbre de Merkel racine, et les enfants de chaque nœud sont des arbres signés avec la signature WOTS de la racine du parent correspondante.


Enfin, les feuilles de l’hyper-arbre sont utilisée pour signer le message (elles signent les clés publiques d’un few-time signature scheme appelé PORS, spécifique à Gravity-SPHINCS).


Une différence importante entre SPHINCS et Gravity-SPHINCS est la possibilité de mettre en cache le nœud racine. Cette possibilité n’est pas utilisée dans le challenge.

### Injection de fautes

Que se passe-t-il lorsqu’une faute est injectée lors de la signature, en particulier lors du calcul du chemin d’authentification ? Dans Gravity-SPHINCS, les signatures sont déterministes : la signature d’un même message avec une clé donnée sera toujours identique.

Une instance WOTS ne peut signer qu’un seul message. Cela garantit la sécurité de la signature.

En cas de faute, un message *différent* va être signé avec les mêmes instances WOTS. WOTS étant, comme son nom l’indique, un one-time signature scheme, il ne devrait pas être possible de signer des messages différents avec un tel système. Des injections répétées au même endroit vont permettre de retrouver toutes les valeurs secrètes d’une instance WOTS.


Une attaque par faute de SPHINCS et de ses dérivés est décrite dans Grafting Trees: a Fault Attack against the SPHINCS framework [<https://eprint.iacr.org/2018/102.pdf>]. Une autre attaque sur SPHINCS a été publiée dans « Practical Fault Injection Attacks on SPHINCS » [<https://eprint.iacr.org/2018/674.pdf>], mais la généralisation à Gravity-SPHINCS décrite dans le papier ne nous a pas semblé immédiate. Il est apparu que nous avons utilisé la méthode la plus directe décrite dans le premier article (cf. Par. « 3.3.1 Total break on WOTS »), sans trop le savoir, les conditions d’un CTF, étant souvent incompatibles avec la lecture d’un papier académique. C’est l’attaque qui nécessite le plus de signatures fautées pour fonctionner. Nous avons, après la résolution, lu plus en détail l’article et nous sommes rendus compte que des attaques nécessitant moins de fautes (une seule faute, en réalité) était possible.

## Attaque

### Principe général

L’attaque va consister dans un premier temps à demander au serveur de signer le même message plusieurs fois. Il va retourner soit la vraie signature, soit une signature sur une entrée fautée dans un des layers du Merkle tree.

L’injection répétée de fautes sur le serveur va permettre de récupérer un certain nombre de messages différents signés par une même instance WOTS sur chaque layer du Merkle tree. On considère ces messages $(x_1, x_2, x_{l-1})$ uniformément aléatoires ($x_l$ est laissé de côté par souci de simplification : il vaut 1 avec une forte probabilité). Chaque valeur $x_i$ pourra valoir 0 avec une probabilité de $1/16$. La signature d’un $x_i$ valant 0 donne la clé privée associée $s_i$. Avec plusieurs messages signés avec la même instance WOTS, il devient possible de récupérer tous les $s_i$.

La probabilité de retrouver la clé privée avec $n$ messages fautés sur une même instance WOTS est :

$\left(1 - \left(\frac{w-1}{w})^n\right)\right)^{l-1}$, soit ici $\left(1 - \left(\frac{15}{16})^n\right)\right)^{66}$. 71 messages suffisent pour casser complètement une signature WOTS avec une probabilité de ~50 %, et ainsi signer n’importe quel message.


Une fois la clé WOTS retrouvée, nous pouvons attacher un arbre arbitraire et le signer avec cette clé. Il est alors possible de signer n’importe quel message pour une instance de Gravity-SPHINCS. Il faut pour cela que l’index du FTS du message à signer soit le même que celui du message d’origine. Il est possible de forcer cela en faisant varier les données aléatoires en début de signature (cf. implémentation). La recherche se fait complètement offline. De plus, l’arbre d’authentification Octopus, passé sous silence pour des raisons de simplicité, reconstruit lui aussi à partir de ces données aléatoires, doit également être valide.


Nous avons mesuré expérimentalement que la probabilité de générer un arbre Octopus valide était d’environ $1/18$. Il y a 32 index possibles pour le FTS. Ainsi, l’obtention d’une seed pour la signature correcte pour un message se fait en moyenne après $2^{9.17}$ itérations.

### Implémentation

Nous avons réécrit une implémentation complète de Gravity-SPHINCS en Python, afin de prototyper plus rapidement les attaques. Une implémentation Python de Haraka développée pour le challenge de Kudelski de l’année précédente a été au départ réutilisée, mais elle était trop lente. Des bindings Python pour un code C ont donc été utilisés.


Un premier script récupère des signatures pour un message donné. Il conserve ceux contenant une faute pour le layer choisi pour l’attaque (nous avons choisi l’avant dernier layer). Le serveur renvoie une signature contenant une faute dans un cas sur deux. Le layer dans lequel se situe la faute est aléatoire. 7x2 requêtes vers le serveur sont donc nécessaires en moyenne pour retrouver une signature fauté intéressante.


Un second script prend les signatures retenues et détermine s’il est possible de retrouver totalement la clé privée WOTS pour le layer donné.


Nous avons demandé 1310 signatures au serveur. Parmi celles-ci, 654 contenaient une faute, et pour 80 signatures, la faute était dans le layer attaqué. 67 signatures ont suffi pour retrouver la clé secrète.


On obtient le flag :

```shell
$ python get_flag.py
Private key recovered with 67 faulted signatures.
CTF{b3c4u53 7h3r3 15 4 l4w 5uch 45 6r4v17y, 7h3 un1v3r53 c4n 4nd w1ll cr3473 1753lf fr0m n07h1n6}
```


