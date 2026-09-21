-- ============================================
-- DEECHAT
-- GC + CREDITS + CHATROOM GAMES DATABASE
-- ============================================

-- 1. Add currencies to profiles
ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS gc bigint NOT NULL DEFAULT 0;

ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS credits bigint NOT NULL DEFAULT 0;

ALTER TABLE public.profiles
ADD CONSTRAINT profiles_gc_nonnegative
CHECK (gc >= 0);

ALTER TABLE public.profiles
ADD CONSTRAINT profiles_credits_nonnegative
CHECK (credits >= 0);


-- 2. Currency transaction history
CREATE TABLE IF NOT EXISTS public.currency_transactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    currency text NOT NULL CHECK (currency IN ('gc','credits')),
    amount bigint NOT NULL,
    transaction_type text NOT NULL,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS currency_transactions_user_idx
ON public.currency_transactions(user_id, created_at DESC);


-- 3. Chatroom games
CREATE TABLE IF NOT EXISTS public.room_games (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text,
    min_players integer NOT NULL DEFAULT 2,
    max_players integer NOT NULL DEFAULT 4,
    entry_credits bigint NOT NULL DEFAULT 1,
    status text NOT NULL DEFAULT 'waiting'
        CHECK (status IN ('waiting','active','finished','cancelled')),
    winner_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

ALTER TABLE public.room_games
ADD CONSTRAINT room_games_players_valid
CHECK (
    min_players >= 2
    AND max_players >= min_players
);

ALTER TABLE public.room_games
ADD CONSTRAINT room_games_entry_valid
CHECK (entry_credits > 0);


-- 4. Players in games
CREATE TABLE IF NOT EXISTS public.room_game_players (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    game_id uuid NOT NULL REFERENCES public.room_games(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    entry_paid bigint NOT NULL DEFAULT 0,
    position integer,
    finished boolean NOT NULL DEFAULT false,
    joined_at timestamptz NOT NULL DEFAULT now(),

    UNIQUE(game_id,user_id)
);

CREATE INDEX IF NOT EXISTS room_game_players_game_idx
ON public.room_game_players(game_id);

CREATE INDEX IF NOT EXISTS room_game_players_user_idx
ON public.room_game_players(user_id);


-- 5. Enable RLS
ALTER TABLE public.currency_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.room_games ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.room_game_players ENABLE ROW LEVEL SECURITY;


-- 6. Publicly viewable game information
DROP POLICY IF EXISTS "games_select_authenticated"
ON public.room_games;

CREATE POLICY "games_select_authenticated"
ON public.room_games
FOR SELECT
TO authenticated
USING (true);


DROP POLICY IF EXISTS "game_players_select_authenticated"
ON public.room_game_players;

CREATE POLICY "game_players_select_authenticated"
ON public.room_game_players
FOR SELECT
TO authenticated
USING (true);


-- 7. Users can view their own currency history
DROP POLICY IF EXISTS "currency_transactions_own_select"
ON public.currency_transactions;

CREATE POLICY "currency_transactions_own_select"
ON public.currency_transactions
FOR SELECT
TO authenticated
USING (user_id = auth.uid());


-- 8. Prevent normal clients from directly
-- inserting/updating currency transactions.
REVOKE INSERT, UPDATE, DELETE
ON public.currency_transactions
FROM anon, authenticated;


-- 9. Securely join a game
CREATE OR REPLACE FUNCTION public.join_room_game(
    p_game_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := auth.uid();
    v_game public.room_games%ROWTYPE;
    v_balance bigint;
    v_players integer;
BEGIN

    IF v_user IS NULL THEN
        RAISE EXCEPTION 'You must be logged in.';
    END IF;

    SELECT *
    INTO v_game
    FROM public.room_games
    WHERE id = p_game_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Game not found.';
    END IF;

    IF v_game.status <> 'waiting' THEN
        RAISE EXCEPTION 'This game is not accepting players.';
    END IF;

    SELECT COUNT(*)
    INTO v_players
    FROM public.room_game_players
    WHERE game_id = p_game_id;

    IF v_players >= v_game.max_players THEN
        RAISE EXCEPTION 'Game is full.';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.room_game_players
        WHERE game_id = p_game_id
        AND user_id = v_user
    ) THEN
        RAISE EXCEPTION 'You already joined this game.';
    END IF;

    SELECT credits
    INTO v_balance
    FROM public.profiles
    WHERE id = v_user
    FOR UPDATE;

    IF v_balance < v_game.entry_credits THEN
        RAISE EXCEPTION 'Not enough Credits.';
    END IF;

    UPDATE public.profiles
    SET credits = credits - v_game.entry_credits
    WHERE id = v_user;

    INSERT INTO public.room_game_players(
        game_id,
        user_id,
        entry_paid
    )
    VALUES(
        p_game_id,
        v_user,
        v_game.entry_credits
    );

    INSERT INTO public.currency_transactions(
        user_id,
        currency,
        amount,
        transaction_type,
        reason
    )
    VALUES(
        v_user,
        'credits',
        -v_game.entry_credits,
        'game_entry',
        'Entry fee for ' || v_game.name
    );

    SELECT COUNT(*)
    INTO v_players
    FROM public.room_game_players
    WHERE game_id = p_game_id;

    IF v_players >= v_game.min_players THEN
        UPDATE public.room_games
        SET status = 'active'
        WHERE id = p_game_id;
    END IF;

    RETURN jsonb_build_object(
        'success', true,
        'game_id', p_game_id,
        'players', v_players
    );
END;
$$;


REVOKE EXECUTE
ON FUNCTION public.join_room_game(uuid)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.join_room_game(uuid)
TO authenticated;


-- 10. Secure game completion
CREATE OR REPLACE FUNCTION public.finish_room_game(
    p_game_id uuid,
    p_winner_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := auth.uid();
    v_game public.room_games%ROWTYPE;
    v_pot bigint;
    v_is_staff boolean;
BEGIN

    IF v_user IS NULL THEN
        RAISE EXCEPTION 'You must be logged in.';
    END IF;

    SELECT EXISTS(
        SELECT 1
        FROM public.profiles
        WHERE id = v_user
        AND site_role IN (
            'owner',
            'super_admin',
            'admin',
            'head_mod'
        )
    )
    INTO v_is_staff;

    IF NOT v_is_staff THEN
        RAISE EXCEPTION 'Only authorized staff can finish games.';
    END IF;

    SELECT *
    INTO v_game
    FROM public.room_games
    WHERE id = p_game_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Game not found.';
    END IF;

    IF v_game.status = 'finished' THEN
        RAISE EXCEPTION 'Game already finished.';
    END IF;

    IF NOT EXISTS(
        SELECT 1
        FROM public.room_game_players
        WHERE game_id = p_game_id
        AND user_id = p_winner_id
    ) THEN
        RAISE EXCEPTION 'Winner is not a player in this game.';
    END IF;

    SELECT COALESCE(SUM(entry_paid),0)
    INTO v_pot
    FROM public.room_game_players
    WHERE game_id = p_game_id;

    UPDATE public.profiles
    SET credits = credits + v_pot
    WHERE id = p_winner_id;

    INSERT INTO public.currency_transactions(
        user_id,
        currency,
        amount,
        transaction_type,
        reason
    )
    VALUES(
        p_winner_id,
        'credits',
        v_pot,
        'game_win',
        'Won ' || v_game.name
    );

    UPDATE public.room_game_players
    SET finished = true
    WHERE game_id = p_game_id;

    UPDATE public.room_games
    SET
        status = 'finished',
        winner_id = p_winner_id,
        finished_at = now()
    WHERE id = p_game_id;

    RETURN jsonb_build_object(
        'success', true,
        'pot', v_pot,
        'winner_id', p_winner_id
    );
END;
$$;


REVOKE EXECUTE
ON FUNCTION public.finish_room_game(uuid,uuid)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.finish_room_game(uuid,uuid)
TO authenticated;