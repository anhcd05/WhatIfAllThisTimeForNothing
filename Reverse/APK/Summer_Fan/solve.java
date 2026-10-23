public final class MainActivityKt {
    
    private static final List<Integer> FLAG = CollectionsKt.listOf((Object[]) new Integer[]{220, 211, 180, 230, 192, 22, 341, 220, 227, 341, 139, 163, 355, 293, 333, 196, 142, 216, 376, 133, 248, 26, 342, 378, 231, 149, 145, 173, 185, 1, 10, 198});

    private static final List<String> KEY = CollectionsKt.listOf((Object[]) new String[]{"h", "o", "t", "_", "h", "o", "t", "_", "s", "u", "m", "m", "m", "e", "r", "r"});

    // KEY = "hot_hot_summmerr"

    public static final List<Integer> getFLAG() {
        return FLAG;
    }

    public static final List<String> getKEY() {
        return KEY;
    }

        private final String generateFlag() {
        ArrayList arrayList = new ArrayList();
        int size = MainActivityKt.getFLAG().size();
        for (int i = 0; i < size; i++) {
            arrayList.add(Character.valueOf((char) ((MainActivityKt.getFLAG().get(i).intValue() ^ StringsKt.first(MainActivityKt.getKEY().get(i % MainActivityKt.getKEY().size()))) - gen(i))));
        }
        return CollectionsKt.joinToString$default(arrayList, "", null, null, 0, null, null, 62, null);
    }

    private final int gen(int i) {
        int size = MainActivityKt.getKEY().size();
        return (((int) Math.pow(i, 3.0d)) % 256) ^ StringsKt.first(MainActivityKt.getKEY().get(size - ((i % size) + 1)));
    }




}


