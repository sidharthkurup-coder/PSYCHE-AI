"""PSYCHE KNOWLEDGE VAULT — Encrypted Personal Knowledge & Goal Repository (REQ-SUB-01).

Provides:
- Encrypted storage (`AES-256-GCM` + DPAPI master key via `PsycheDatabase`) for user-authored
  goal manifestos, personal notes, relationship boundaries, and reference documents.
- Non-empty AAD binding (`context_aad = f"vault:{vault_item_id}"`) preventing record swapping.
- Full lifecycle CRUD (`add_item`, `get_item`, `update_item`, `delete_item`, `list_items`) with
  explicit NumPy vector zeroization on deletion or update.
- Hybrid semantic cosine + lexical/phonetic search across all 7 authorized language modes.
"""

from __future__ import annotations

import json
import re
from typing import Any

from core.contracts.validator import normalize_phonetic_search_key
from core.storage.database import PsycheDatabase, utc_now_iso


class PsycheKnowledgeVaultEngine:
    """Dedicated subsystem manager for encrypted PSYCHE KNOWLEDGE VAULT items."""

    VALID_CATEGORIES = {"GOAL_MANIFESTO", "PERSONAL_NOTE", "BOUNDARY_RULE", "REFERENCE", "DOCUMENT"}

    def __init__(self, db: PsycheDatabase) -> None:
        self.db = db

    def add_item(
        self,
        *,
        title: str,
        category: str,
        content: str,
        language_modes: list[str] | None = None,
    ) -> str:
        """Encrypts and indexes a new item inside knowledge_vault_items."""
        return self.db.add_knowledge_vault_item(
            title=title,
            category=category,
            content=content,
            language_modes=language_modes,
        )

    def get_item(self, vault_item_id: str) -> dict[str, Any] | None:
        """Retrieves and decrypts a Knowledge Vault item by ID."""
        return self.db.get_knowledge_vault_item(vault_item_id)

    def update_item(
        self,
        vault_item_id: str,
        *,
        title: str | None = None,
        category: str | None = None,
        content: str | None = None,
        language_modes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Updates title, category, encrypted content, or vector index of an existing vault item."""
        conn = self.db.connection
        row = conn.execute(
            "SELECT * FROM knowledge_vault_items WHERE vault_item_id = ?", (vault_item_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Knowledge Vault item {vault_item_id} not found")

        existing = self.db.get_knowledge_vault_item(vault_item_id)
        assert existing is not None

        new_title = title if title is not None else existing["title"]
        new_category = category if category is not None else existing["category"]
        new_content = content if content is not None else existing["content"]
        new_modes = language_modes if language_modes is not None else existing["language_modes"]

        new_emb_idx = row["embedding_row_index"]
        if title is not None or content is not None:
            # Zero out previous embedding row if present before appending updated vector
            old_idx = row["embedding_row_index"]
            if old_idx is not None and 0 <= int(old_idx) < self.db._vectors.shape[0]:
                self.db._vectors[int(old_idx)] = 0.0
            new_emb_idx = self.db.append_embedding(f"{new_title}\n{new_content}")

        encrypted_blob = self.db.vault.encrypt_text(
            new_content, context_aad=f"vault:{vault_item_id}"
        )
        now_iso = utc_now_iso()
        conn.execute(
            """
            UPDATE knowledge_vault_items
            SET title = ?,
                category = ?,
                content_encrypted_blob = ?,
                language_modes_json = ?,
                embedding_row_index = ?,
                updated_at_utc = ?
            WHERE vault_item_id = ?
            """,
            (
                new_title,
                new_category,
                encrypted_blob,
                json.dumps(new_modes),
                new_emb_idx,
                now_iso,
                vault_item_id,
            ),
        )
        conn.commit()
        updated = self.get_item(vault_item_id)
        assert updated is not None
        return updated

    def delete_item(self, vault_item_id: str) -> bool:
        """Deletes a Knowledge Vault item and zeroizes its vector row in RAM & on disk."""
        conn = self.db.connection
        row = conn.execute(
            "SELECT embedding_row_index FROM knowledge_vault_items WHERE vault_item_id = ?",
            (vault_item_id,),
        ).fetchone()
        if row is None:
            return False

        emb_idx = row["embedding_row_index"]
        if emb_idx is not None and 0 <= int(emb_idx) < self.db._vectors.shape[0]:
            self.db._vectors[int(emb_idx)] = 0.0
            self.db.save_vectors()

        conn.execute("DELETE FROM knowledge_vault_items WHERE vault_item_id = ?", (vault_item_id,))
        conn.commit()
        return True

    def list_items(self, category: str | None = None) -> list[dict[str, Any]]:
        """Lists decrypted Knowledge Vault items, optionally filtered by category."""
        conn = self.db.connection
        if category is not None:
            rows = conn.execute(
                "SELECT vault_item_id FROM knowledge_vault_items WHERE category = ? ORDER BY updated_at_utc DESC",
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT vault_item_id FROM knowledge_vault_items ORDER BY updated_at_utc DESC"
            ).fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            item = self.get_item(r["vault_item_id"])
            if item is not None:
                results.append(item)
        return results

    def search_vault(
        self,
        *,
        query_text: str,
        category: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Hybrid semantic cosine + phonetic lexical search over encrypted Knowledge Vault items."""
        conn = self.db.connection
        if category is not None:
            rows = conn.execute(
                "SELECT vault_item_id, category, embedding_row_index FROM knowledge_vault_items WHERE category = ?",
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT vault_item_id, category, embedding_row_index FROM knowledge_vault_items"
            ).fetchall()

        if not rows:
            return []

        emb_indices = [
            int(r["embedding_row_index"]) for r in rows if r["embedding_row_index"] is not None
        ]
        sim_scores = self.db.cosine_similarity_scores(query_text, emb_indices)
        q_tokens = set(re.findall(r"\w+", normalize_phonetic_search_key(query_text)))

        scored: list[tuple[float, dict[str, Any]]] = []
        for r in rows:
            vid = r["vault_item_id"]
            item = self.get_item(vid)
            if item is None:
                continue
            idx = r["embedding_row_index"]
            s_vec = sim_scores.get(int(idx), 0.5) if idx is not None else 0.5
            item_tokens = set(
                re.findall(
                    r"\w+",
                    normalize_phonetic_search_key(f"{item['title']} {item['content']}"),
                )
            )
            s_lex = (
                len(q_tokens & item_tokens) / len(q_tokens)
                if q_tokens and item_tokens
                else 0.0
            )
            cat_boost = 0.15 if item["category"] in {"GOAL_MANIFESTO", "BOUNDARY_RULE"} else 0.0
            total = round(0.55 * s_vec + 0.30 * s_lex + cat_boost, 4)
            enriched = dict(item)
            enriched["retrieval_score"] = total
            scored.append((total, enriched))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [it for _, it in scored[:top_k]]
